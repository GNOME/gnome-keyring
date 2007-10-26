/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-secure-memory.h - library for allocating memory that is non-pageable

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

/*
 * IMPORTANT: This is pure vanila standard C, no glib. We need this 
 * because certain consumers of this protocol need to be built 
 * without linking in any special libraries. ie: the PKCS#11 module.
 */

#include "config.h"

#include "gkr-secure-memory.h"

#include <sys/mman.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#define DEBUG_SECURE_MEMORY 0

#if DEBUG_SECURE_MEMORY 
#define DEBUG_ALLOC(msg, n) 	fprintf(stderr, "%s %lu bytes\n", msg, n); 
#else
#define DEBUG_ALLOC(msg, n)
#endif

#define DEFAULT_BLOCK_SIZE 16384

/* Use our own assert to guarantee no glib allocations */
#ifndef ASSERT
#ifdef G_DISABLE_ASSERT
#define ASSERT(x) 
#else 
#define ASSERT(x) assert(x)
#endif
#endif

#define DO_LOCK() \
	gkr_memory_lock (); 
	
#define DO_UNLOCK() \
	gkr_memory_unlock ();


/* -----------------------------------------------------------------------------
 * BLOCK SUBALLOCATION
 */

/* suba - sub-allocate memory from larger chunk of memory
 * Copyright (c) 2003 Michael B. Allen <mba2000 ioplex.com>
 *
 * The MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

typedef size_t ref_t;  /* suba offset from start of memory to object */

#define SUBA_MAGIC "\xFF\x15\x15\x15SUBA"
#define CELL_MAGIC 0x7777CE11
#define ALIGNMASK 1U
#define ALIGN(s) (((s) + ALIGNMASK) & ~ALIGNMASK)
#define POFF (ALIGN(sizeof(size_t)) + ALIGN(sizeof(unsigned int)))
#define C2P(c) ((char *)(c) + POFF)
#define P2C(p) ((struct cell *)((char *)(p) - POFF))
#define ISADJ(c1,c2) ((struct cell *)(C2P(c1) + (c1)->size) == (struct cell *)(c2))
#define SREF(s,p) (ref_t)((char *)(p) - (char *)(s))
#define SADR(s,r) (void *)((char *)(s) + (r))
#define RECLAIM_DEPTH_MAX 2

struct allocator {
	unsigned char magic[8];                /* suba header identifier */
	ref_t tail;                 /* offset to first cell in free list */
	size_t mincell;    /* min cell size must be at least sizeof cell */
	size_t size;                        /* total size of memory area */
	size_t alloc_total;  /* total bytes utilized from this allocator */
	size_t free_total;   /* total bytes released from this allocator */
	size_t size_total;  /* total bytes requested from this allocator */
	ref_t userref;
};

struct cell {
	size_t size;
	unsigned int magic;
	ref_t next; /* reference to next cell in free list */
};

static void*
suba_addr (const struct allocator *suba, const ref_t ref)
{
	if (suba && ref > 0 && ref <= suba->size) {
		return (char *)suba + ref;
	}
	return NULL;
}

static ref_t
suba_ref (const struct allocator *suba, const void *ptr)
{
	if (suba && ptr) {
		ref_t ref = (char *)ptr - (char *)suba;
		if (ref > 0 && ref <= suba->size) {
			return ref;
		}
	}
	return 0;
}

static struct allocator *
suba_init (void *mem, size_t size, size_t mincell)
{
	struct allocator *suba = mem;
	size_t hdrsiz;
	struct cell *c;

	hdrsiz = ALIGN(sizeof *suba);

	ASSERT (mem != NULL);
	ASSERT (size > (hdrsiz + POFF));

	memset(suba, 0, hdrsiz);
	memcpy(suba->magic, SUBA_MAGIC, 8);
	suba->tail = hdrsiz;
	suba->mincell = mincell < ALIGN (sizeof (*c)) ? ALIGN (sizeof (*c)) : ALIGN (mincell);
	suba->size = size;

	c = suba_addr(suba, hdrsiz);
	c->size = size - (hdrsiz + POFF);
	c->next = suba->tail;

	return suba;
}

static void *
suba_alloc(struct allocator *suba, size_t size)
{
	struct cell *c1, *c2, *c3;
	size_t s = size;

	size = size < suba->mincell ? suba->mincell : ALIGN(size);

	c2 = SADR(suba, suba->tail);
	for ( ;; ) {
		c1 = c2;
		if ((c2 = suba_addr(suba, c1->next)) == NULL) {
			errno = EFAULT;
			return NULL;
		}
		if (c2->size >= size) {
			break;       /* found a cell large enough */
		}
		if (c1->next == suba->tail) {
			return NULL;
		}
	}

	if ((c2->size - size) > suba->mincell) {
									/* split new cell */
		c3 = (struct cell *)(C2P(c2) + size);
		c3->size = c2->size - (size + POFF);
		if (c1 == c2) {
			c1 = c3;
		} else {
			c3->next = c2->next;
		}
		c1->next = SREF(suba, c3);
		c2->size = size;
		if (c2 == SADR(suba, suba->tail)) {
			suba->tail = SREF(suba, c3);
		}
	} else if (c1->next == suba->tail) {
                /* never use the last cell! */
	} else {                   
		/* use the entire cell */
		c1->next = c2->next;
	}

	suba->alloc_total += POFF + c2->size;
	suba->size_total += s;
	
	c2->magic = CELL_MAGIC;
	DEBUG_ALLOC ("gkr-secure-memory: allocated ", (unsigned long)size);

	/* TODO: Fix suba, so always allocates zero */
	memset (C2P(c2), 0, size);
	
	return C2P(c2);
}

static void
suba_free(void *suba0, void *ptr)
{
	struct allocator *suba = suba0;
	struct cell *c1, *c2, *c3;
	volatile char *vp;
	size_t len;
	ref_t ref;
	int j1, j2;

	if (!ptr) 
		return;

       	c1 = SADR(suba, suba->tail);

	/* Find out what cell we're talking about */
	c2 = P2C(ptr);
	if ((ref = suba_ref(suba, c2)) == 0) {
		ASSERT(0 && "invalid memory pointer passed to gkr-secure-memory");
		return;
	}
	if (c2->magic != CELL_MAGIC) {
		ASSERT(0 && "invalid memory pointer passed to gkr-secure-memory");
		return;
	}
		 
	/* Clear out memory */
        vp = (volatile char*)ptr;
       	len = c2->size;
        while (len) { 
        	*vp = 0xaa;
        	vp++;
        	len--; 
        } 

	suba->free_total += POFF + c2->size;
	suba->alloc_total -= (POFF + c2->size);

	c2->magic = 0;
	DEBUG_ALLOC ("gkr-secure-memory: freed ", (unsigned long)c2->size);
	
	/* splice the cell back into the list */
	if (c2 > c1) {           /* append to end of list */
		if (ISADJ(c1,c2)) {    /* join with last cell */
			c1->size += POFF + c2->size;
			return;
		}
		c2->next = c1->next;
		suba->tail = c1->next = ref;
		return;
	}

	while (c1->next < ref) {   /* find insertion point */
		c1 = SADR(suba, c1->next);
	}
	c3 = SADR(suba, c1->next);

	j1 = ISADJ(c1,c2); /* c1 and c2 need to be joined */
	j2 = ISADJ(c2,c3); /* c2 and c3 need to be joined */

	if (j1) {
		if (j2) {  /* splice all three cells together */
			if (SREF(suba, c3) == suba->tail) {
				suba->tail = SREF(suba, c1);
			}
			c1->next = c3->next;
			c1->size += POFF + c3->size;
		}
		c1->size += POFF + c2->size;
	} else {
		if (j2) {
			if (SREF(suba, c3) == suba->tail) {
				suba->tail = ref;
			}
			c2->next = c3->next == SREF(suba, c3) ? ref : c3->next;
			c2->size += POFF + c3->size;
		} else {
			c2->next = c1->next;
		}
		c1->next = ref;
	}
}

static void *
suba_realloc(struct allocator *suba, void *ptr, size_t size)
{
	struct cell *c;
	void *p;

	if (ptr == NULL)
		return suba_alloc(suba, size);
	if (size == 0) {
		suba_free(suba, ptr);
		return NULL;
	}
	c = P2C(ptr);
	if (c->size < size || (c->size - ALIGN(size)) > suba->mincell) {
		p = suba_alloc(suba, size);
	} else {
		return ptr;
	}
	if (p) {
		memcpy(p, ptr, c->size);
		suba_free(suba, ptr);
	}

	return p;
}

static int
suba_print_cell(struct allocator *suba, const char *msg, struct cell *c)
{
	ref_t ref = suba_ref(suba, c);
	if (ref >= ALIGN(sizeof *suba) && (ref + POFF + c->size) <= 10000000) {
		fprintf(stderr, "%s: %8u-%-8u %8u %-8u\n", msg,
			(unsigned int)ref, (unsigned int)(ref + POFF + c->size),
			(unsigned int)c->size, (unsigned int)c->next);
	} else {
		fprintf(stderr, "%s: %8u-err %8u %-8u\n", msg,
			(unsigned int)ref, (unsigned int)c->size,
			(unsigned int)c->next);
		return 0;
	}
	return 1;
}

static int
suba_print_free_list(struct allocator *suba)
{
	struct cell *c;
	char buf[10];
	int count = 0;
	int ret = 1;

	c = suba_addr(suba, suba->tail);
	while (c->next < suba->tail) {
		c = suba_addr(suba, c->next);
		sprintf(buf, "%d", count++);
		if (!suba_print_cell(suba, buf, c)) {
			ret = 0;
		}
	}
	c = suba_addr(suba, c->next);
	sprintf(buf, "%d", count++);
	if (!suba_print_cell(suba, buf, c)) {
		ret = 0;
	}

	return ret;
}

static size_t
suba_allocation_size (struct allocator *suba, void *ptr)
{
	struct cell *c = P2C(ptr);
	if (c->magic != CELL_MAGIC) {
		ASSERT(0 && "invalid memory pointer passed to gkr-secure-memory");
		return 0;
	}
	return c->size;
}

/* -----------------------------------------------------------------------------
 * PAGE SOURCE -- Where blocks of locked memory pages come from.
 */
 
static int lock_warning = 1;

static void*
get_locked_pages (unsigned long *sz)
{
	void *pages;
	unsigned long pgsize;
	
	ASSERT (sz);
	ASSERT (*sz);

	/* Make sure sz is a multiple of the page size */
	pgsize = getpagesize ();
	*sz = (*sz + pgsize -1) & ~(pgsize - 1);
		
#ifndef HAVE_MLOCK
	if (lock_warning)
		fprintf (stderr, "your system does not support private memory");
	lock_warning = 0;
	return NULL;
#else
	pages = mmap (0, *sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (pages == MAP_FAILED) {
		if (lock_warning)
			fprintf (stderr, "couldn't map %lu bytes of private memory: %s\n", 
			         *sz, strerror (errno));
		lock_warning = 0;
		return NULL;
	}
	
	if (mlock (pages, *sz) < 0) {
		if (lock_warning)
			fprintf (stderr, "couldn't lock %lu bytes of private memory: %s\n", 
			         *sz, strerror (errno));
		lock_warning = 0;
		munmap (pages, *sz);
		return NULL;
	}
	
	DEBUG_ALLOC ("gkr-secure-memory: new block ", *sz);
	
	lock_warning = 1;
	return pages;
#endif
}

static void 
rel_locked_pages (void *pages, unsigned long sz)
{
	ASSERT (pages);
	ASSERT (sz % getpagesize () == 0);
	
#ifndef HAVE_MLOCK
	ASSERT (FALSE);
#else
	if (munlock (pages, sz) < 0)
		fprintf (stderr, "couldn't unlock private memory: %s\n", strerror (errno));
		
	if (munmap (pages, sz) < 0)
		fprintf (stderr, "couldn't unmap private anonymous memory: %s\n", strerror (errno));
		
	DEBUG_ALLOC ("gkr-secure-memory: freed block ", sz);
#endif
}

/* -----------------------------------------------------------------------------
 * MANAGE DIFFERENT BLOCKS
 */

typedef struct _MemBlock {
	unsigned long size;
	struct allocator *suba;
	struct _MemBlock *next;
} MemBlock;

static MemBlock *most_recent_block = NULL;

static MemBlock* 
block_create (unsigned long size)
{
	MemBlock *bl;
	void *blmem;
	
	size += sizeof (MemBlock);
	
	/* The size above is a minimum, we're free to go bigger */
	if (size < DEFAULT_BLOCK_SIZE)
		size = DEFAULT_BLOCK_SIZE;
		
	blmem = get_locked_pages (&size);
	if (!blmem)
		return NULL;
		
	bl = (MemBlock*)blmem;
	bl->size = size;
	bl->suba = suba_init (((unsigned char*)blmem) + sizeof (MemBlock), 
			      size - sizeof (MemBlock), 32);
	ASSERT (bl->suba);
	
	bl->next = most_recent_block;
	most_recent_block = bl;
	
	return bl;
}

static void
block_destroy (MemBlock *bl)
{
	MemBlock *b;
	
	ASSERT (bl && bl->suba);
	ASSERT (bl->size > 0);
	ASSERT (bl->suba->alloc_total == 0);
	
	/* Is the most recent block, simple */
	if (bl == most_recent_block) {
		most_recent_block = bl->next;
		
	/* Take it out of our list */
	} else {
		for (b = most_recent_block; b; b = b->next) {
			if (b->next == bl) {
				b->next = bl->next;
				break;
			}
		}
		ASSERT (b != NULL && "couldn't find memory block in list");
	}
	
	/* Memory is all in one block, nothing fancy to free */
	rel_locked_pages(bl, bl->size);	
}

static int
block_belongs (MemBlock *bl, void *p)
{
	ASSERT (bl);
	ASSERT (bl->size > 0);
	
	/* This does not check for invalid memory */
	return ((char*)p) >= ((char*)bl) && 
	       ((char*)p) < (((char*)bl) + bl->size);
}

void*
gkr_secure_memory_alloc (unsigned long sz)
{
	MemBlock *bl;
	void *p = NULL;
		
	if (sz > 0xFFFFFFFF / 2) {
		fprintf (stderr, "tried to allocate an insane amount of memory: %lu\n", sz);   
		return NULL;
	}
	
	DO_LOCK ();
	
		for (bl = most_recent_block; bl; bl = bl->next) {
			p = suba_alloc (bl->suba, sz);
			if (p)
				break;	
		}
	
		/* None of the current blocks have space, allocate new */
		if (!p) {
			bl = block_create (sz);
			if (bl) {
				p = suba_alloc (bl->suba, sz);
				ASSERT (p);
			}
		}
	
	DO_UNLOCK ();
	
	if (!p)
		errno = ENOMEM;
	
	return p;
}

void*
gkr_secure_memory_realloc (void *p, unsigned long sz)
{
	MemBlock *bl = NULL;
	unsigned long oldsz = 0;
	int donew = 0;
	void *n = NULL;	
	
	if (sz > 0xFFFFFFFF / 2) {
		fprintf (stderr, "tried to allocate an insane amount of memory: %lu\n", sz);   
		return NULL;
	}
	
	if (p == NULL)
		return gkr_secure_memory_alloc (sz);
	if (!sz) {
		gkr_secure_memory_free (p);
		return NULL;
	}
	
	DO_LOCK ();
	
		/* Find out where it belongs to */
		for (bl = most_recent_block; bl; bl = bl->next) {
			if (block_belongs (bl, p)) {
				oldsz = suba_allocation_size (bl->suba, p); 
				n = suba_realloc (bl->suba, p, sz);
				break;
			}
		}

		/* If it didn't work we may need to allocate a new block */
		if (bl && !n)
			donew = 1;

		if (bl && bl->suba->alloc_total == 0)
			block_destroy (bl);
		
	DO_UNLOCK ();		
	
	if (!bl) {
		fprintf (stderr, "memory does not belong to gnome-keyring: 0x%08lx\n", (unsigned long)p);
		ASSERT (0 && "memory does does not belong to gnome-keyring");
		return NULL;
	}
		
	if (donew) {
		n = gkr_secure_memory_alloc (sz);
		if (n) {
			memcpy (n, p, oldsz);
			gkr_secure_memory_free (p);
		}
	}
	
	if (!n)
		errno = ENOMEM;

	return n;
}

void
gkr_secure_memory_free (void *p)
{
	MemBlock *bl = NULL;
	
	DO_LOCK ();
	
		/* Find out where it belongs to */
		for (bl = most_recent_block; bl; bl = bl->next) {
			if (block_belongs (bl, p)) {
				suba_free (bl->suba, p);
				break;
			}
		}

		if (bl && bl->suba->alloc_total == 0)
			block_destroy (bl);
			
	DO_UNLOCK ();
	
	if (!bl) {
		fprintf (stderr, "memory does not belong to gnome-keyring: 0x%08lx\n", (unsigned long)p);
		ASSERT (0 && "memory does does not belong to gnome-keyring");
	}
} 

int  
gkr_secure_memory_check (void *p)
{
	MemBlock *bl = NULL;

	DO_LOCK ();
	
		/* Find out where it belongs to */
		for (bl = most_recent_block; bl; bl = bl->next) {
			if (block_belongs (bl, p))
				break;
		}
		
	DO_UNLOCK ();
	
	return bl == NULL ? 0 : 1;
} 

unsigned long
gkr_secure_memory_size (void* p)
{
	MemBlock *bl = NULL;
	unsigned long sz;

	DO_LOCK ();
	
		/* Find out where it belongs to */
		for (bl = most_recent_block; bl; bl = bl->next) {
			if (block_belongs (bl, p)) {
				sz = suba_allocation_size (bl->suba, p); 
				break;
			}
		}
		
	DO_UNLOCK ();
	
	if (!bl) {
		fprintf (stderr, "memory does not belong to gnome-keyring: 0x%08lx\n", (unsigned long)p);
		ASSERT (0 && "memory does does not belong to gnome-keyring");
	}
	
	return sz;
}

void
gkr_secure_memory_dump (void)
{
	MemBlock *bl = NULL;

	DO_LOCK ();
	
		/* Find out where it belongs to */
		for (bl = most_recent_block; bl; bl = bl->next) {
			fprintf (stderr, "----------------------------------------------------\n");
			fprintf (stderr, "  BLOCK at: 0x%08lx  len: %lu\n", (unsigned long)bl, bl->size);
			fprintf (stderr, "\n");
			suba_print_free_list (bl->suba);
		}
		
	DO_UNLOCK ();
}
