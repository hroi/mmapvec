//! Author: Hroi Sigurdsson
//!
//! Low-level VM page backed container.
//! Memory is allocated directly from ```mmap()```/```VirtualAlloc()```.
//!
//! # TODO
//! - Implement for Windows (```VirtualAlloc()```).
//! - ```IndexMut``` trait.
//! - ```Index<Range<u32>>``` trait.
//! - ```Iterator``` trait.

#![no_std]

#![cfg_attr(feature = "nightly", feature(test))]
#[cfg(feature = "nightly")]
extern crate test;

use core::mem;
use core::ops;
use core::ptr;


#[cfg(unix)]
extern crate libc;

#[cfg(windows)]
extern crate kernel32;

pub struct MmapVec<T> {
    ptr: *mut T,
    /// Number of contained items.
    pub len: usize,
    bytes: usize,
}

fn grow_step(current: usize) -> usize {
    match current {
        0 => 1,
        n => n * 2
    }
}

impl<T> MmapVec<T> {

    /// Returns an empty container. No allocation is performed.
    pub fn new() -> MmapVec<T> {
        MmapVec {
            ptr: ptr::null_mut(),
            len: 0,
            bytes: 0,
        }
    }

    /// Returns a container with preallocated capacity for _at least_ ```cap``` items
    /// (rounded to nearest page size, usually 4 KB).
    pub fn with_capacity(cap: usize) -> MmapVec<T> {
        let mut ret = Self::new();
        ret.grow(cap);
        ret
    }

    pub unsafe fn get_unchecked<'a>(&self, index: usize) -> &'a T {
        &*self.ptr.offset(index as isize)
    }

    /// Returns a reference to item at ```index```.
    /// # Panics
    /// - if index is out of bounds.
    pub fn get<'a>(&self, index: usize) -> &'a T {
        assert!(index < self.len);
        unsafe { self.get_unchecked(index) }
    }

    /// Inserts item at ```index```. Items after index are moved to make place.
    /// Will reallocate space if out of capacity.
    /// # Panics
    /// - if index is out of bounds.
    pub fn insert(&mut self, index: usize, val: T) {
        assert!(index < self.len);

        if self.cap() <= self.len {
            // out of capacity, allocate more space
            let new_cap = grow_step(self.cap());
            self.grow(new_cap);
        }

        unsafe {
            let dst_ptr = self.ptr.offset(index as isize);
            ptr::copy(dst_ptr, dst_ptr.offset(1), self.len - index);
            ptr::write(dst_ptr, val);
        }

        self.len += 1;
    }

    /// Removes item at ```index```.
    /// Items after index are moved into the remaining place.
    /// This will *not* free any memory.
    /// # Panics
    /// - if index is out of bounds.
    pub fn remove(&mut self, index: usize) -> T {
        assert!(index < self.len);

        self.len -= 1;

        let ret: T;
        unsafe {
            let src_ptr = self.ptr.offset(index as isize);
            ret = ptr::read(src_ptr);
            ptr::copy(src_ptr.offset(1), src_ptr, self.len - index);
        }

        ret
    }

    /// Push item to end of container.
    /// Will reallocate space if out of capacity.
    pub fn push(&mut self, elem: T) {
        if self.cap() <= self.len {
            // out of space, allocate more space
            let new_cap = grow_step(self.cap());
            self.grow(new_cap);
        }

        unsafe {
            let dst_ptr = self.ptr.offset(self.len as isize);
            ptr::write(dst_ptr, elem);
        }

        self.len += 1;
    }

    /// Pop item from end of container.
    /// This will *not* free any memory.
    /// # Panics
    /// - if container is empty
    pub fn pop(&mut self) -> T {
        assert!(!self.is_empty());

        self.len -= 1;
        unsafe {
            ptr::read(self.ptr.offset((self.len) as isize))
        }
    }

    /// Returns the container's capacity.
    /// Will always return ```0``` if T is zero-sized.
    pub fn cap(&self) -> usize {
        if mem::size_of::<T>() == 0 {
            0
        } else {
            self.bytes / mem::size_of::<T>()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> MmapVecIter<T> {
        MmapVecIter {
            inner: self,
            pos: 0,
        }
    }

    #[cfg(not(unix))]
    fn grow(&mut self, new_cap: usize) {
        notimplemented!()
    }

    #[cfg(unix)]
    fn grow(&mut self, new_cap: usize) {
        if mem::size_of::<T>() == 0 {
            return
        }

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let min_bytes_to_alloc = new_cap * mem::size_of::<T>();
        let pages_needed = match min_bytes_to_alloc % page_size as usize {
            0 => min_bytes_to_alloc / page_size as usize,
            _ => (min_bytes_to_alloc / page_size as usize) + 1,
        };
        let bytes_to_alloc = pages_needed * page_size as usize;

        unsafe {
            let new_ptr = libc::mmap(ptr::null_mut(), bytes_to_alloc,
                                     libc::PROT_READ | libc::PROT_WRITE,
                                     libc::MAP_ANON  | libc::MAP_PRIVATE,
                                     -1, 0) as *mut T;
            if new_ptr == libc::MAP_FAILED as *mut T {
                libc::perror(b"mmap\0".as_ptr() as *const libc::c_char);
                panic!();
            }

            ptr::copy_nonoverlapping(self.ptr, new_ptr as *mut T, self.cap());

            if !self.ptr.is_null() {
                let munmap_result = libc::munmap(self.ptr as *mut libc::c_void, self.bytes);
                if munmap_result != 0 {
                    libc::perror(b"munmap\0".as_ptr() as *const libc::c_char);
                    panic!();
                }
            }

            self.ptr = new_ptr;
            self.bytes = bytes_to_alloc;
        }
    }

}

pub struct MmapVecIter<'a, T: 'a> {
    inner: &'a MmapVec<T>,
    pos: usize,
}

impl<'a, T: 'a> Iterator for MmapVecIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if self.pos == self.inner.len {
            return None;
        }

        let ret = unsafe {self.inner.get_unchecked(self.pos)};
        self.pos += 1;
        Some(ret)
    }
}

impl<T> ops::Index<usize> for MmapVec<T> {
    type Output = T;

    fn index<'a>(&self, index: usize) -> &'a T {
        self.get(index)
    }
}

impl<T> Drop for MmapVec<T> {

    #[cfg(not(unix))]
    fn drop(&mut self) {
        unimplemented!()
    }

    #[cfg(unix)]
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            while !self.is_empty() {
                self.pop(); // and drop
            }

            unsafe {
                if libc::munmap(self.ptr as *mut libc::c_void, self.bytes) != 0 {
                    libc::perror(b"munmap\0".as_ptr() as *const libc::c_char);
                    panic!();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        // an empty vector should not allocate anything
        let v: MmapVec<u32> = MmapVec::new();
        assert_eq!(v.cap(), 0);
        assert!(v.ptr.is_null());
    }

    #[test]
    fn with_capacity() {
        let min_cap = (!0u32 / 8u32) as usize;
        let v: MmapVec<u32> = MmapVec::with_capacity(min_cap);
        assert_eq!(v.len, 0);
        assert!(v.cap() >= min_cap);
    }

    #[test]
    fn push() {
        let mut v: MmapVec<u32> = MmapVec::new();
        v.push(123);
        assert!(v.cap() > 0);
    }

    #[test]
    fn pop() {
        let mut v: MmapVec<u32> = MmapVec::new();
        v.push(123);
        assert_eq!(v.len, 1);
        assert_eq!(v.pop(), 123);
        assert_eq!(v.len, 0);
    }

    #[test]
    #[should_panic]
    fn pop_empty() {
        let mut v: MmapVec<u32> = MmapVec::new();
        v.pop();
    }

    #[test]
    fn zero_sized() {
        let mut v: MmapVec<()> = MmapVec::new();
        v.push(());
        assert_eq!(v.pop(), ());
    }

    #[test]
    fn get() {
        let mut v: MmapVec<u32> = MmapVec::new();
        for i in 0..10 {
            v.push(i);
        }
        assert_eq!(v.get(0), &0);
        assert_eq!(v.get(1), &1);
        assert_eq!(v.get(9), &9);
    }

    #[test]
    #[should_panic]
    fn get_oob() {
        let mut v: MmapVec<u32> = MmapVec::new();
        for i in 0..10 {
            v.push(i);
        }
        v.get(10);
    }

    #[test]
    fn insert() {
        let mut v: MmapVec<u32> = MmapVec::new();
        for i in 0..10 {
            v.push(i);
        }
        v.insert(4, 123);
        assert_eq!(v[4], 123);
    }

    #[test]
    #[should_panic]
    fn insert_oob() {
        let mut v: MmapVec<u32> = MmapVec::new();
        v.insert(4, 123);
    }

    #[test]
    fn remove() {
        let mut v: MmapVec<u32> = MmapVec::new();
        for i in 0..10 {
            v.push(i);
        }
        assert_eq!(v.remove(0), 0);
        assert_eq!(v.remove(0), 1);
        assert_eq!(v.remove(7), 9);
    }

    #[test]
    #[should_panic]
    fn remove_oob() {
        let mut v: MmapVec<u32> = MmapVec::new();
        v.push(123);
        v.remove(10);
    }

    #[test]
    fn index() {
        let mut v: MmapVec<u32> = MmapVec::new();
        for i in 0..10 {
            v.push(i);
        }
        assert_eq!(v[0], 0);
        assert_eq!(v[1], 1);
        assert_eq!(v[9], 9);
    }

    #[test]
    #[should_panic]
    fn index_oob() {
        let mut v: MmapVec<u32> = MmapVec::new();
        for i in 0..10 {
            v.push(i);
        }
        v[10];
    }

    #[test]
    fn push_to_grow() {
        let mut v: MmapVec<u32> = MmapVec::new();
        let elems = 10000;
        for i in 0..elems {
            v.push(i);
        }
        for i in 0..elems {
            assert_eq!(v.pop(), elems - 1 - i);
        }
        assert_eq!(v.len, 0);
    }

    #[test]
    fn iter() {
        let mut v: MmapVec<u32> = MmapVec::new();
        let elems = 3;
        for i in 0..elems {
            v.push(i);
        }
        let mut it = v.iter();
        assert_eq!(it.next(), Some(&0));
        assert_eq!(it.next(), Some(&1));
        assert_eq!(it.next(), Some(&2));
        assert!(it.next().is_none());
    }

    #[cfg(feature = "nightly")]
    mod bench {
        use ::MmapVec;
        use test::{Bencher, black_box};

        #[bench]
        fn push_10m(b: &mut Bencher) {
            b.iter(|| {
                let n_items = 10_000_000;
                let mut v: MmapVec<u32> = MmapVec::new();
                for i in 0..n_items {
                    v.push(i);
                }
            });
        }

        #[bench]
        fn push_10m_prealloc(b: &mut Bencher) {
            b.iter(|| {
                let n_items = 10_000_000u32;
                let mut v: MmapVec<u32> = MmapVec::with_capacity(n_items as usize);
                for i in 0..n_items {
                    v.push(i);
                }
            });
        }

        #[bench]
        fn pop(b: &mut Bencher) {
            let n_items = 10_000_000u32;
            let mut v: MmapVec<u32> = MmapVec::with_capacity(n_items as usize);
            for i in 0..n_items {
                v.push(i);
            }
            assert!(!v.is_empty());
            assert_eq!(v.len, n_items as usize);
            b.iter(|| {
                black_box(v.pop());
            });
        }

        #[bench]
        fn iter_10m(b: &mut Bencher) {
            let n_items = 1_000_000u32;
            let mut v: MmapVec<u32> = MmapVec::with_capacity(n_items as usize);
            for i in 0..n_items {
                v.push(i);
            }
            b.iter(|| {
                for x in v.iter() {
                    black_box(x);
                }
            });
        }
    }
}

