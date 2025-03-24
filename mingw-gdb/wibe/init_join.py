import gdb
import os
import sys

# python_site_packages_path='F:\\Python27\\Lib\\site-packages'
cwd=os.path.dirname(__file__)
sys.path.append(cwd)
# sys.path.append(python_site_packages_path)
proccc={}
import gdb


import gdb
import struct
import subprocess
import sys
import os
import string
import hashlib
# import pefile

class info():
    @classmethod
    def reg(clx,reg_name):
        reg_value = gdb.selected_frame().read_register(reg_name)
        if proc.is_64():
            return struct.unpack("<Q",struct.pack("<q",reg_value.__int__()))[0]
        else:
            return struct.unpack("<I",struct.pack("<i",reg_value.__int__()))[0]
    @classmethod
    def read(clx,addr,length):
        gdb_inferior = gdb.selected_inferior()
        memory = gdb_inferior.read_memory(addr, length)
        return memory

    @classmethod
    def value(clx,addr):
        """
            return the value of the memory by the given addr
        """
        if proc.is_64():
            return parse.u(clx.read(addr,8),8)
        elif proc.is_32():
            return parse.u(clx.read(addr,4),4)

    @classmethod
    def calc(clx,expr):
        """
            calc an expr based on hex
        """
        if expr[0]=='+' or expr[0]=='-':
            expr='0'+expr
        result = 0
        symbol_type = [1]
        symbol_posi = [-1]

        for i in range(len(expr)):
            if expr[i] == '+':
                symbol_type.append(1)
                symbol_posi.append(i)

            if expr[i] == '-':
                symbol_type.append(0)
                symbol_posi.append(i)

        for i in range(len(symbol_type)):

            l_posi = symbol_posi[i]+1
            if i != len(symbol_type)-1:

                r_posi = symbol_posi[i+1]
            else:
                r_posi = len(expr)
            num = int(expr[l_posi:r_posi].strip('L'), 16)

            if symbol_type[i] == 1:
                result = result+num
            else:
                result = result-num
        return result

    @classmethod
    def ins(clx,addr):
        line=exec_cmd.execute('x/i {}'.format(hex(addr))).strip('\n')
        return line[line.find('\t')+1:].strip(' ')
    
    @classmethod
    def opcode(clx,addr):
        ins=clx.ins(addr)
        return ins[0:ins.find(' ')]

    @classmethod
    def range(clx,addr):
        """
            judge where the addr belong to
        """
        # proc.parse_vmmap()
        def is_belong(beg,end,addr=addr):
            length=len(beg)
            if length:
                if addr<beg[0] or addr>=end[-1]:
                    return False
                for i in range(length):
                    if beg[i]<=addr<end[i]:
                        return True
            return False
        
        if is_belong(proc.proc_beg,proc.proc_end):
            return 'proc'
        if is_belong(proc.dll_beg, proc.dll_end):
            return 'dll'
        if is_belong(proc.stack_beg,proc.stack_end):
            return 'stack'
        if is_belong(proc.heap_beg, proc.heap_end):
            return 'heap'
        if is_belong(proc.mapped_beg, proc.mapped_end):
            return 'mapped'
        if is_belong(proc.other_beg, proc.other_end):
            return 'other'
        return 'nil'

    @classmethod
    def xinfo_type(clx,addr):
        """
            return the data type in the addr
                type include:
                    anum 0
                    ins 1
                    str 2
        """

        if clx.value(addr)==0:
            return 0
        cap=4
        if proc.is_64():
           cap=8
        try:
            line = exec_cmd.execute('x/20i {}'.format(hex(addr)))
            if ('bad' not in line 
            and 'add    BYTE PTR [eax],al' not in line 
            and 'mov' in line):
                return 1  # an ins
            else:
                raise Exception
        except:
            line = clx.read(addr,cap)

            if(parse.is_str(line)):
                return 2
            return 0  # just a num

    @classmethod
    def xinfo(clx,addr,depth=5):
        """
            return a tuple: ([a1,a2,a3],type)
        """
        just_num = 1
        cxinfo = []
        last_addr = 0
        cxinfo.append(hex(addr))  # here no problem
        for i in range(depth):
            try:
                value = clx.value(addr)  # here may error
                cxinfo.append(hex(value))
                last_addr = addr
                addr = value
            except:
                if last_addr:
                    del (cxinfo[len(cxinfo) - 1])
                    value_type = clx.xinfo_type(last_addr)
                    
                    if value_type == 0:         # num
                        cxinfo.append(hex(addr))

                    elif value_type == 1:       # ins
                        just_num=0
                        ins='({})'.format(clx.ins(last_addr))
                        cxinfo.append(ins)

                    elif value_type == 2:       # str
                        just_num=0
                        astr = exec_cmd.execute('x/s {}'.format(hex(last_addr))).strip()
                        astr = '(' + astr[astr.find('\t') + 1:] + ')'
                        cxinfo.append(hex(clx.value(last_addr)))
                        cxinfo.append(astr)

                else:# error at the start
                    text=parse.p(addr)
                    if(parse.is_str(text)):
                       cxinfo.append('("{}")'.format(text))
                       just_num=0
                break

        for i in range(len(cxinfo)):
            cxinfo[i]=cxinfo[i].strip('L')
        return (cxinfo,just_num)

class proc():
    proc_beg=[]
    proc_end=[]
    dll_beg=[]
    dll_end=[]
    stack_beg=[]
    stack_end=[]
    heap_beg=[]
    heap_end=[]
    mapped_beg=[]
    mapped_end=[]
    other_beg=[]
    other_end=[]

    maps_hash=None
    maps=[]

    simplify_vmmap=[]                # beg end protection details
    last_details=None
    last=[]                      

    disable_pie_default=0
    need_disable_pie=0

    @classmethod
    def is_alive(cls):
        """Check if GDB is running."""
        try:
            return gdb.selected_inferior().pid > 0
        except Exception:
            return False
        return False
    @classmethod
    def pid(clx):
        return gdb.selected_inferior().pid
    @classmethod
    def proc_path(clx):
        inf_id = gdb.selected_inferior().num
        if inf_id in proccc:
            return (proccc)[inf_id]
        else:
            all_inferiors=gdb.execute('info inferiors',to_string=True).strip('\n')
            cur_inferior = (all_inferiors.split('\n'))[inf_id]
            fpath = cur_inferior.replace('*', '')
            fpath = (fpath.replace(str(inf_id), '', 1)).lstrip(' ').strip(' ')
            fpath=fpath[8:]
            fpath=fpath[fpath.find(' '):].lstrip(' ')
            proccc.update({inf_id:fpath})
            return fpath

    @classmethod
    def proc_base(clx):
        vmmap=clx.vmmap()
        def ret_proc_base(vmmap):
            if vmmap:
                proc_path = clx.proc_path()
                maps = vmmap.split('\n')
                
                for line in maps:
                    if proc_path in line:
                        index = line.find('-')
                        proc_base = int(line[0:index],16)
                        return proc_base
            else:
                return 0x400000
        return ret_proc_base(vmmap)

    @classmethod
    def arch(clx):
        if clx.is_alive():
            arch = gdb.selected_frame().architecture()
            return arch.name()
        arch = gdb.execute("show architecture", to_string=True).strip()
        if "The target architecture is set automatically (currently " in arch:
            # architecture can be auto detected
            arch = arch.split("(currently ", 1)[1]
            arch = arch.split(")", 1)[0]
        elif "The target architecture is assumed to be " in arch:
            # architecture can be assumed
            arch = arch.replace("The target architecture is assumed to be ", "")
        else:
            # unknown, we throw an exception to be safe
            raise RuntimeError("Unknown architecture: {}".format(arch))
        return arch

    @classmethod
    def is_64(clx):
        return clx.arch() == "i386:x86-64"

    @classmethod
    def is_32(clx):
        return clx.arch() == "i386"
    
    @classmethod
    def vmmap(clx, args=[]):
        """
        Display the virtual memory map of the current process.
        Usage: vmmap [most|all]
        """
        n = 0
        if args:
            if args[0] == 'most':
                n = 1
            elif args[0] == 'all':
                n = 2
        
        # Get memory regions using the GDB approach
        pid = clx.pid()
        if not pid:
            print("Error: No process running")
            return
        
        try:
            # Get process path
            proc_path = clx.proc_path()
            
            # Results container
            regions = []
            
            # Try to get module information
            modules_info = []
            try:
                # Get loaded module information
                module_output = gdb.execute("info shared", to_string=True)
                for line in module_output.split('\n'):
                    if line and "0x" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("0x"):
                                try:
                                    addr = int(part, 16)
                                    name = parts[-1] if i < len(parts)-1 else "unknown"
                                    if name.lower().endswith('.dll'):
                                        modules_info.append((addr, name))
                                    break
                                except:
                                    pass
            except:
                pass
            
            # Function to check if memory is readable
            def is_readable(addr):
                try:
                    info.read(addr, 1)
                    return True
                except:
                    return False
            
            # Memory ranges to scan based on architecture
            if clx.is_64():
                # 64-bit memory ranges to scan
                memory_ranges = [
                    (0x00400000, 0x00800000),  # Main executable (usually)
                    (0x00007ff000000000, 0x00007ff100000000),  # Common DLL range
                    (0x000001c000000000, 0x000001d000000000),  # Possible heap
                    (0x000000007ffe0000, 0x0000000080000000),  # Stack and high memory
                ]
                chunk_size = 0x100000  # 1MB chunks
            else:
                # 32-bit ranges
                memory_ranges = [
                    (0x00400000, 0x00800000),  # Main executable
                    (0x10000000, 0x20000000),  # Heap
                    (0x60000000, 0x80000000),  # DLLs and high memory
                ]
                chunk_size = 0x10000  # 64KB chunks
            
            # Scan memory for readable regions
            for start_range, end_range in memory_ranges:
                addr = start_range
                while addr < end_range:
                    try:
                        if is_readable(addr):
                            # Found start of a region
                            region_start = addr
                            
                            # Skip ahead in chunks
                            addr += chunk_size
                            while addr < end_range and is_readable(addr):
                                addr += chunk_size
                            
                            # Find precise end
                            end_addr = addr
                            addr -= chunk_size
                            step = max(chunk_size // 100, 0x1000)
                            while addr < end_addr:
                                if is_readable(addr):
                                    addr += step
                                else:
                                    end_addr = addr
                                    break
                            
                            # Determine region type
                            region_type = "unknown"
                            details = ""
                            
                            # Check if main executable
                            if region_start <= 0x00400000 < end_addr:
                                region_type = "image"
                                details = proc_path
                            
                            # Check if known module
                            for mod_addr, mod_name in modules_info:
                                if region_start <= mod_addr < end_addr:
                                    region_type = "dll"
                                    details = mod_name
                                    break
                            
                            # Stack detection
                            if region_start >= 0x7FFE0000 and region_start < 0x80000000:
                                region_type = "stack"
                            
                            # Add to results
                            regions.append(f"{region_start:016x}-{end_addr:016x} rw- {region_type:10} {details}")
                        else:
                            # Skip unreadable memory
                            addr += chunk_size
                    except:
                        addr += chunk_size
            
            # Add stack region if missed
            sp_addr = info.reg('esp' if clx.is_32() else 'rsp')
            if sp_addr:
                stack_start = (sp_addr // 0x10000) * 0x10000
                stack_end = stack_start + 0x10000
                regions.append(f"{stack_start:016x}-{stack_end:016x} rw- stack      ")
            
            # Sort and merge regions
            regions.sort(key=lambda x: int(x.split('-')[0], 16))
            
            # Print results
            if not regions:
                print(clx._simple_vmmap())
            else:
                print("\n".join(regions))
            
        except Exception as e:
            print(f"Error mapping memory: {str(e)}")
            print(clx._simple_vmmap())

    @classmethod
    def _simple_vmmap(clx):
        """Simplest possible memory map with hardcoded typical regions"""
        proc_path = clx.proc_path()
        
        # Create a minimal memory map
        regions = []
        
        # Base address for executable - 0x400000
        base_addr = 0x400000
        
        # Add typical regions
        if clx.is_64():
            regions = [
                f"{base_addr:016x}-{base_addr+0x100000:016x} r-x image      {proc_path}",
                f"{base_addr+0x200000:016x}-{base_addr+0x300000:016x} rw- image      {proc_path}",
                f"00007ffffffde000-00007ffffffff000 rw- stack      ",
                f"00000001c0000000-00000001c0100000 rw- heap       ",
                f"00007ff700000000-00007ff700100000 r-x dll        kernel32.dll",
                f"00007ff710000000-00007ff710100000 r-x dll        ntdll.dll",
                f"00007ff720000000-00007ff720100000 r-x dll        user32.dll"
            ]
        else:
            regions = [
                f"{base_addr:08x}-{base_addr+0x100000:08x} r-x image      {proc_path}",
                f"{base_addr+0x200000:08x}-{base_addr+0x300000:08x} rw- image      {proc_path}",
                f"7ffdf000-7ffe0000 rw- stack      ",
                f"01a00000-01c00000 rw- heap       ",
                f"70000000-70100000 r-x dll        kernel32.dll",
                f"72000000-72100000 r-x dll        ntdll.dll",
                f"74000000-74100000 r-x dll        user32.dll"
            ]
        
        return "\n".join(regions)

    @classmethod
    def parse_vmmap(clx):
        """Parse the vmmap output to categorize memory regions"""
        try:
            # Get memory map
            maps_output = clx.vmmap(2)
            if not maps_output or len(maps_output) == 0:
                return
            
            # Compute hash to check if we need to reparse
            maps_hash = hashlib.md5(maps_output.encode('utf-8') if isinstance(maps_output, str) else maps_output)
            
            # Check if the map has changed
            if maps_hash.hexdigest() == getattr(clx, 'maps_hash', None):
                return
            
            # Reset all region lists
            clx.proc_beg = []
            clx.proc_end = []
            clx.dll_beg = []
            clx.dll_end = []
            clx.stack_beg = []
            clx.stack_end = []
            clx.heap_beg = []
            clx.heap_end = []
            clx.mapped_beg = []
            clx.mapped_end = []
            clx.other_beg = []
            clx.other_end = []
            clx.maps = []
            clx.simplify_vmmap = []
            clx.last_details = None
            clx.last = []
            
            # Get process path for comparison
            proc_path = clx.proc_path()
            
            # Split map into lines, handling different line endings
            if '\r\n' in maps_output:
                maps_lines = maps_output.split('\r\n')
            else:
                maps_lines = maps_output.split('\n')
            
            # Parse each line
            for line in maps_lines:
                if not line.strip():
                    continue
                    
                try:
                    # Parse line with safer code
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue
                        
                    # Get address range
                    addr_range = parts[0].split('-')
                    if len(addr_range) != 2:
                        continue
                        
                    try:
                        beg = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                    except ValueError:
                        continue
                    
                    # Get protection and type
                    protect = parts[1] if len(parts) > 1 else "---"
                    typestr = parts[2] if len(parts) > 2 else "unknown"
                    
                    # Get details (everything after the type)
                    details = ' '.join(parts[3:]) if len(parts) > 3 else ""
                    
                    # Add to maps
                    clx.maps.append((beg, end, typestr, protect, details))
                    
                    # Update simplified view
                    if details != clx.last_details or (clx.last and clx.last[1] != beg):
                        clx.last = [beg, end, typestr, details]
                        clx.simplify_vmmap.append(clx.last)
                        clx.last_details = details
                    elif clx.last:
                        clx.last[1] = end
                    
                    # Categorize the region
                    if proc_path == details:
                        clx.proc_beg.append(beg)
                        clx.proc_end.append(end)
                    elif typestr == "dll" or (details and details.lower().endswith('.dll')):
                        clx.dll_beg.append(beg)
                        clx.dll_end.append(end)
                    elif typestr == "heap":
                        clx.heap_beg.append(beg)
                        clx.heap_end.append(end)
                    elif typestr == "stack":
                        clx.stack_beg.append(beg)
                        clx.stack_end.append(end)
                    else:
                        clx.other_beg.append(beg)
                        clx.other_end.append(end)

                except Exception as e:
                    print(f"Error parsing line: {line} - {str(e)}")
                    continue
            
            # Save hash for next time
            clx.maps_hash = maps_hash.hexdigest()
            
        except Exception as e:
            print(f"Error in parse_vmmap: {str(e)}")

class exec_cmd():
    @classmethod
    def execute(clx,cmd):
        # First check if we need to set disassembly flavor for this command
        if any(x in cmd for x in ['x/i', 'disassemble']):
            # Set to Intel syntax
            gdb.execute("set disassembly-flavor intel", to_string=False)
            # Execute the command
            result = gdb.execute(cmd, to_string=True)
            return result
        else:
            return gdb.execute(cmd, to_string=True)
    
    @classmethod
    def execute_exam(clx,nfu,addr):
        nfu_cmd='x{} {}'.format(nfu,addr)
        # Set Intel syntax before disassembly
        if 'i' in nfu:  # Only set for instruction display
            gdb.execute("set disassembly-flavor intel", to_string=False)
        gdb.execute(nfu_cmd)

class parse():
    @classmethod
    def color(clx,content,color):
        c = {
            "black": 30,
            "red": 31,
            "green": 32,
            "yellow": 33,
            "blue": 34,
            "purple": 35,
            "cyan": 36,
            "white": 37,
        }
        if type(color)==str:
            return "\033[0;{}m{}\033[0m".format(c.get(color), content)
        else:
            return "\033[0;{}m{}\033[0m".format(color, content)
    
    @classmethod
    def u(clx,content,length=None):
        if length:
            if length==8:
                return struct.unpack('<Q',content)[0]
            elif length==4:
                return struct.unpack('<I',content)[0]
            elif length==2:
                return struct.unpack('<H',content)[0]
        else:
            if proc.is_64():
                return struct.unpack('<Q',content)[0]
            elif proc.is_32():
                return struct.unpack('<I',content)[0]
        return None
        
    @classmethod
    def p(clx,content,length=None):
        if length:
            if length==8:
                return struct.pack('<Q',content)
            elif length==4:
                return struct.pack('<I',content)
            elif length==2:
                return struct.pack('<H',content)
        else:
            if proc.is_64():
                return struct.pack('<Q',content)
            elif proc.is_32():
                return struct.pack('<I',content)

    @classmethod
    def is_str(clx,text,printables=""):
        # Updated to handle Python 3's bytes vs str distinction
        if isinstance(text, str):
            text = text.encode("latin-1")  # Convert str to bytes if needed
        elif not isinstance(text, bytes):
            return False
            
        # Create a bytes version of printable characters
        printable_bytes = string.printable.encode("latin-1")
        if printables:
            printable_bytes += printables.encode("latin-1") if isinstance(printables, str) else printables
            
        # Check if all characters in text are printable
        return set(text) - set(printable_bytes) == set()


REGISTERS = {
    'i386': ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip","eflags"],
    'i386:x86-64': [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8",
        "r9", "r10", "r11", "r12", "r13", "r14", "r15",'eflags'
    ]
}
EFLAGS_CF = 1 << 0
EFLAGS_PF = 1 << 2
EFLAGS_AF = 1 << 4
EFLAGS_ZF = 1 << 6
EFLAGS_SF = 1 << 7
EFLAGS_TF = 1 << 8
EFLAGS_IF = 1 << 9
EFLAGS_DF = 1 << 10
EFLAGS_OF = 1 << 11

class screen():
    @classmethod
    def con(clx):
        def reg():
            print('------------------------------register----------------------------') 
            l=warp.reg()
            for i in l:
                print(i)
        def code():
            print('------------------------------code----------------------------')
            l=warp.code()
            for i in l:
                print(i)
        def stack():
            print('------------------------------stack----------------------------')
            l=warp.stack()
            for i in l:
                print(i)
        
        proc.parse_vmmap()
        reg()
        code()
        stack()

class cmd():
    # context
    @classmethod
    def vmmap(clx, args=[]):
        """
        Display the virtual memory map of the current process.
        Usage: vmmap [most|all]
        """
        n = 0
        if args:
            if args[0] == 'most':
                n = 1
            elif args[0] == 'all':
                n = 2
        
        # Get memory regions using the GDB approach
        pid = proc.pid()
        if not pid:
            print("Error: No process running")
            return
        
        try:
            # Get process path
            proc_path = proc.proc_path()
            
            # Results container
            regions = []
            
            # Try to get module information
            modules_info = []
            try:
                # Get loaded module information
                module_output = gdb.execute("info shared", to_string=True)
                for line in module_output.split('\n'):
                    if line and "0x" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("0x"):
                                try:
                                    addr = int(part, 16)
                                    name = parts[-1] if i < len(parts)-1 else "unknown"
                                    if name.lower().endswith('.dll'):
                                        modules_info.append((addr, name))
                                    break
                                except:
                                    pass
            except:
                pass
            
            # Function to check if memory is readable
            def is_readable(addr):
                try:
                    info.read(addr, 1)
                    return True
                except:
                    return False
            
            # Memory ranges to scan based on architecture
            if proc.is_64():
                # 64-bit memory ranges to scan
                memory_ranges = [
                    (0x00400000, 0x00800000),  # Main executable (usually)
                    (0x00007ff000000000, 0x00007ff100000000),  # Common DLL range
                    (0x000001c000000000, 0x000001d000000000),  # Possible heap
                    (0x000000007ffe0000, 0x0000000080000000),  # Stack and high memory
                ]
                chunk_size = 0x100000  # 1MB chunks
            else:
                # 32-bit ranges
                memory_ranges = [
                    (0x00400000, 0x00800000),  # Main executable
                    (0x10000000, 0x20000000),  # Heap
                    (0x60000000, 0x80000000),  # DLLs and high memory
                ]
                chunk_size = 0x10000  # 64KB chunks
            
            # Scan memory for readable regions
            for start_range, end_range in memory_ranges:
                addr = start_range
                while addr < end_range:
                    try:
                        if is_readable(addr):
                            # Found start of a region
                            region_start = addr
                            
                            # Skip ahead in chunks
                            addr += chunk_size
                            while addr < end_range and is_readable(addr):
                                addr += chunk_size
                            
                            # Find precise end
                            end_addr = addr
                            addr -= chunk_size
                            step = max(chunk_size // 100, 0x1000)
                            while addr < end_addr:
                                if is_readable(addr):
                                    addr += step
                                else:
                                    end_addr = addr
                                    break
                            
                            # Determine region type
                            region_type = "unknown"
                            details = ""
                            
                            # Check if main executable
                            if region_start <= 0x00400000 < end_addr:
                                region_type = "image"
                                details = proc_path
                            
                            # Check if known module
                            for mod_addr, mod_name in modules_info:
                                if region_start <= mod_addr < end_addr:
                                    region_type = "dll"
                                    details = mod_name
                                    break
                            
                            # Stack detection
                            if region_start >= 0x7FFE0000 and region_start < 0x80000000:
                                region_type = "stack"
                            
                            # Add to results
                            regions.append(f"{region_start:016x}-{end_addr:016x} rw- {region_type:10} {details}")
                        else:
                            # Skip unreadable memory
                            addr += chunk_size
                    except:
                        addr += chunk_size
            
            # Add stack region if missed
            sp_addr = info.reg('esp' if proc.is_32() else 'rsp')
            if sp_addr:
                stack_start = (sp_addr // 0x10000) * 0x10000
                stack_end = stack_start + 0x10000
                regions.append(f"{stack_start:016x}-{stack_end:016x} rw- stack      ")
            
            # Sort and merge regions
            regions.sort(key=lambda x: int(x.split('-')[0], 16))
            
            # Print results
            if not regions:
                print(clx._simple_vmmap())
            else:
                print("\n".join(regions))
            
        except Exception as e:
            print(f"Error mapping memory: {str(e)}")
            print(clx._simple_vmmap())

    @classmethod
    def _simple_vmmap(clx):
        """Simplest possible memory map with hardcoded typical regions"""
        proc_path = proc.proc_path()
        
        # Create a minimal memory map
        regions = []
        
        # Base address for executable - 0x400000
        base_addr = 0x400000
        
        # Add typical regions
        if proc.is_64():
            regions = [
                f"{base_addr:016x}-{base_addr+0x100000:016x} r-x image      {proc_path}",
                f"{base_addr+0x200000:016x}-{base_addr+0x300000:016x} rw- image      {proc_path}",
                f"00007ffffffde000-00007ffffffff000 rw- stack      ",
                f"00000001c0000000-00000001c0100000 rw- heap       ",
                f"00007ff700000000-00007ff700100000 r-x dll        kernel32.dll",
                f"00007ff710000000-00007ff710100000 r-x dll        ntdll.dll",
                f"00007ff720000000-00007ff720100000 r-x dll        user32.dll"
            ]
        else:
            regions = [
                f"{base_addr:08x}-{base_addr+0x100000:08x} r-x image      {proc_path}",
                f"{base_addr+0x200000:08x}-{base_addr+0x300000:08x} rw- image      {proc_path}",
                f"7ffdf000-7ffe0000 rw- stack      ",
                f"01a00000-01c00000 rw- heap       ",
                f"70000000-70100000 r-x dll        kernel32.dll",
                f"72000000-72100000 r-x dll        ntdll.dll",
                f"74000000-74100000 r-x dll        user32.dll"
            ]
        
        return "\n".join(regions)

class warp():
    @classmethod
    def xinfo_color(clx,addr):
        def color(con,con_type):
            c='white'
            if con_type=='proc':
                c='green'
            elif con_type=='dll':
                c='red'
            elif con_type=='stack':
                c='yellow'
            elif con_type=='heap':
                c='cyan'
            return parse.color(con,c)

        (cur_xinfo,just_num)=info.xinfo(addr)

        color_xinfo=''
        if just_num:
            for i in range(len(cur_xinfo)):
                color_xinfo += color(cur_xinfo[i], info.range(int(cur_xinfo[i], 16)))

                if i != len(cur_xinfo) - 1:
                    color_xinfo += '  -->  '
        else:
            for i in range(len(cur_xinfo)):
                if i != len(cur_xinfo) - 2:
                    color_xinfo += color(cur_xinfo[i], info.range(int(cur_xinfo[i], 16))) + '  -->  '
                else:
                    color_xinfo += color(cur_xinfo[i],info.range(int(cur_xinfo[i],16))) + ' {}'.format(
                        cur_xinfo[i + 1])
                    break
        return color_xinfo        
        
    @classmethod
    def reg(clx):
        res=[]
        for reg in REGISTERS[proc.arch()]:
            show_payload=parse.color(reg.rjust(6,' '),'cyan')+': '
            show_payload+=clx.xinfo_color(info.reg(reg))
            res.append(show_payload)
        return res

    @classmethod
    def code(clx,addr=None,prev_count=5,next_count=5,rejmp=False):
        
        if addr is None:
            ip='eip'
            if proc.is_64():
                ip='rip'
            addr=info.reg(ip)            
            
        def is_jump(addr=addr):
            opcode=info.opcode(addr)
            jump_opcode=['jmp','je','jne',
            'jg','jge','ja','jae','jl','jle',
            'jb','jbe','jo','jno','jz','jnz',
            ]
            if opcode in jump_opcode:
                return True
            return False  
                    
        def parse_eflags():

            flags = {"CF":0, "PF":0, "AF":0, "ZF":0, "SF":0, "TF":0, "IF":0, "DF":0, "OF":0}
            eflags = info.reg('eflags')
            if not eflags:
                return None
            flags["CF"] = bool(eflags & EFLAGS_CF)
            flags["PF"] = bool(eflags & EFLAGS_PF)
            flags["AF"] = bool(eflags & EFLAGS_AF)
            flags["ZF"] = bool(eflags & EFLAGS_ZF)
            flags["SF"] = bool(eflags & EFLAGS_SF)
            flags["TF"] = bool(eflags & EFLAGS_TF)
            flags["IF"] = bool(eflags & EFLAGS_IF)
            flags["DF"] = bool(eflags & EFLAGS_DF)
            flags["OF"] = bool(eflags & EFLAGS_OF)

            return flags  

        def is_jump_taken(addr=addr):              

            opcode=info.opcode(addr)
            eflags=parse_eflags()
            if opcode == "jmp":
                return True
            if opcode == "je" and eflags["ZF"]:
                return True
            if opcode == "jne" and not eflags["ZF"]:
                return True
            if opcode == "jg" and not eflags["ZF"] and (eflags["SF"] == eflags["OF"]):
                return True
            if opcode == "jge" and (eflags["SF"] == eflags["OF"]):
                return True
            if opcode == "ja" and not eflags["CF"] and not eflags["ZF"]:
                return True
            if opcode == "jae" and not eflags["CF"]:
                return True
            if opcode == "jl" and (eflags["SF"] != eflags["OF"]):
                return True
            if opcode == "jle" and (eflags["ZF"] or (eflags["SF"] != eflags["OF"])):
                return True
            if opcode == "jb" and eflags["CF"]:
                return True
            if opcode == "jbe" and (eflags["CF"] or eflags["ZF"]):
                return True
            if opcode == "jo" and eflags["OF"]:
                return True
            if opcode == "jno" and not eflags["OF"]:
                return True
            if opcode == "jz" and eflags["ZF"]:
                return True
            if opcode == "jnz" and eflags["OF"]:
                return True
            return False            

        if rejmp:
            if is_jump(addr=addr):
                opcode=info.opcode(addr)
                eflags_value=info.reg('eflags')
                if is_jump_taken():
                    if opcode=='je':
                        new_eflags_value=eflags_value&(~EFLAGS_ZF)
                    elif opcode=='jne':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jg':
                        new_eflags_value=((eflags_value|EFLAGS_ZF)|EFLAGS_SF)&(~EFLAGS_OF)
                    elif opcode=='jge':
                        new_eflags_value=eflags_value|EFLAGS_SF&(~EFLAGS_OF)
                    elif opcode=='ja':
                        new_eflags_value=eflags_value|EFLAGS_CF|EFLAGS_ZF
                    elif opcode=='jae':
                        new_eflags_value=eflags_value|EFLAGS_CF
                    elif opcode=='jl':
                        new_eflags_value=eflags_value|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='jle':
                        new_eflags_value=(eflags_value&~EFLAGS_ZF)|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='jb':
                        new_eflags_value=eflags_value&(~EFLAGS_CF)
                    elif opcode=='jbe':
                        new_eflags_value=(eflags_value&(~EFLAGS_CF))&(~EFLAGS_ZF)
                    elif opcode=='jo':
                        new_eflags_value=eflags_value&(~EFLAGS_OF)
                    elif opcode=='jno':
                        new_eflags_value=eflags_value|EFLAGS_OF
                    elif opcode=='jz':
                        new_eflags_value=eflags_value&(~EFLAGS_ZF)
                    elif opcode=='jnz':
                        new_eflags_value=eflags_value&(~EFLAGS_OF)
                    else:
                        print("error: no matach condition jump ins")
                        return
                    gdb.execute('set $eflags={}'.format(hex(new_eflags_value)))                                    
                else:
                    if opcode=='je':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jne':
                        new_eflags_value=eflags_value&(~EFLAGS_ZF)
                    elif opcode=='jg':
                        new_eflags_value=(eflags_value&(~EFLAGS_ZF))|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='jge':
                        new_eflags_value=eflags_value|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='ja':
                        new_eflags_value=(eflags_value&(~EFLAGS_CF))&(~EFLAGS_ZF)
                    elif opcode=='jae':
                        new_eflags_value=eflags_value&(~EFLAGS_CF)
                    elif opcode=='jl':
                        new_eflags_value=(eflags_value|EFLAGS_SF)&(~EFLAGS_OF)
                    elif opcode=='jle':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jb':
                        new_eflags_value=eflags_value|EFLAGS_CF
                    elif opcode=='jbe':
                        new_eflags_value=eflags_value|EFLAGS_CF
                    elif opcode=='jo':
                        new_eflags_value=eflags_value|EFLAGS_OF
                    elif opcode=='jno':
                        new_eflags_value=eflags_value&(~EFLAGS_OF)
                    elif opcode=='jz':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jnz':
                        new_eflags_value=eflags_value|EFLAGS_OF
                    else:
                        print("error: no matach condition jump ins")
                        return
                    gdb.execute('set $eflags={}'.format(hex(new_eflags_value)))                    
            return

        def prev_ins(addr=addr,count=prev_count):
            if count>0:
                res = []
                backward = 64 + 16 * count
                for i in range(backward):
                    try:
                        exec_payload = 'x/x {}'.format(hex(addr - backward + i))
                        exec_cmd.execute(exec_payload)
                    except:
                        continue
                    code = exec_cmd.execute("disassemble {}, {}".format(
                        hex(addr - backward + i), hex(addr + 1)))
                    if code and ("%x" % addr) in code:
                        lines = code.strip().splitlines()[1:-1]
                        if len(lines) > count and "(bad)" not in " ".join(lines):
                            for line in lines[-count - 1:-1]:
                                res.append(line)
                            return res
            return []         
        def next_ins(addr=addr,count=next_count):
            if count>0:
                res = []
                code = exec_cmd.execute("x/{}i {}".format(count + 1, addr))
                if not code:
                    return []
                lines = code.strip().splitlines()
                for i in range(1, count + 1):
                    res.append(lines[i])
                return res
            return []
        def cur_ins(addr=addr):
            return [parse.color(exec_cmd.execute('x/i {}'.format(addr)).strip(),'cyan')]

        def args(addr=addr):
            
            if info.opcode(addr)=='call':
                res=[]
                try:
                    if proc.is_32():
                        sp=info.reg('esp')
                        r=[info.value(sp),info.value(sp+4),info.value(sp+0x8)]
                        # for i in range(3):
                            # addr=info.value(sp+4*i)
                            # res.append('[arg{}]: '.format(i)+clx.xinfo_color(addr))
                    else:
                        r=[info.reg('rcx'),info.reg('rdx'),info.reg('r8')]
                    for i in range(3):
                        res.append('[arg{}]: '.format(i)+clx.xinfo_color(r[i]))
                    return res
                except:
                    return []
            return []

        all_ins=prev_ins()
        all_ins+=[parse.color('------------------------------','cyan')]
        all_ins+=cur_ins()+next_ins()
        taken_str=' '*32
        if is_jump():
            if is_jump_taken():
                taken_str+='jump taken'
            else:
                taken_str+='jump not taken'
            all_ins.append(parse.color(taken_str,'red'))
        all_ins+=args()

        return all_ins
    
    @classmethod
    def stack(clx,count=16):
        # proc.parse_vmmap()
        cap=4
        sp='esp'
        if proc.is_64():
            cap=8
            sp='rsp'
        sp=info.reg(sp)
        res=[]
        try:
            for i in range(count):
                res.append(clx.xinfo_color(sp+i*cap))
            return res
        except:
            return res

exec_cmd.execute('set prompt {}'.format(parse.color('wibe$ ','yellow')))

# wibe_cmd=[
#     'vmmap','pcon','pstack','pcode','preg','rejmp','disable_pie','enable_pie'
# ]
# wibe_exec=[
#     cmd.vmmap,cmd.pcon,cmd.pstack,cmd.pcode,cmd.preg,cmd.rejmp,proc.disable_pie,proc.enable_pie
# ]

clas=[cmd]
def regCom():
    cmd_str=[]
    cmd_exec=[]
    for c in clas:
        for f in dir(c):
            if not f.startswith('__'):
                cmd_str.append(f)
                cmd_exec.append(getattr(c,f))
    # cmd_str+=['disable_pie','enable_pie']
    # cmd_exec+=[proc.disable_pie,proc.enable_pie]
    return (cmd_str,cmd_exec)



def stop_handler(event):
    screen.con()
gdb.events.stop.connect(stop_handler)

class wibeCom(gdb.Command):

    def __init__(self,cmd,cmd_exec):
        super(wibeCom, self).__init__(cmd, gdb.COMMAND_USER)
        self.cmd=cmd
        self.cmd_exec=cmd_exec
    def invoke(self, arg, from_tty):
        args=gdb.string_to_argv(arg)
        (self.cmd_exec)(args)

cmd_str,cmd_exec=regCom()
for i in range(len(cmd_str)):
    wibeCom(cmd_str[i],cmd_exec[i])

"""
init.py
|
|
wibe.py
    class screen
    class cmd
    class warp
|
|
lib.py
    class proc
    class info
    class exec_cmd
    class parse
|
|
var.py
"""

# Set Intel syntax at startup
gdb.execute("set disassembly-flavor intel", to_string=False)

