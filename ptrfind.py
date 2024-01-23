try:
    import gdb 
except ImportError:
    print("[-] This command cannot run as standalone. See README for details.")
    exit(1)

import argparse
from types import SimpleNamespace
import copy

class PtrFind (gdb.Command):
  COLOR_OK = "\033[92m"  # GREEN
  COLOR_WARNING = "\033[93m"  # YELLOW
  COLOR_FAIL = "\033[91m"  # RED
  COLOR_BOLD = "\033[1m"
  COLOR_RESET = "\033[0m"

  little_endian = "little endian" in gdb.execute("show endian", to_string=True)
  pointer_size = gdb.lookup_type('void').pointer().sizeof
  proc_mapping = None
  

  def __init__ (self):
    super (PtrFind, self).__init__ ("ptrfind", gdb.COMMAND_USER)

  def print_msg(msg):
    print(PtrFind.COLOR_OK + PtrFind.COLOR_BOLD + "[+] " + PtrFind.COLOR_RESET + msg)

  def print_error(msg):
    print(PtrFind.COLOR_FAIL + PtrFind.COLOR_BOLD + "[-] " + PtrFind.COLOR_RESET + msg)

  def print_warning(msg):
    print(PtrFind.COLOR_WARNING + PtrFind.COLOR_BOLD + "[!] " + PtrFind.COLOR_RESET + msg)

  def invoke (self, arg, from_tty):
    parser = argparse.ArgumentParser(
                    prog='ptrfind',
                    description='Helps you find pointers in your program.',
                    epilog="""TODO: Explanation of address format\n
                    For more information, check [insert repo url here]""")
    parser.add_argument('find_region', metavar="<destination region>")
    parser.add_argument('--chain', action='store_true', help="enables leak-chains")
    parser.add_argument('--leaks', action='store_true', help="look for outgoing leaks in the provided section. The destination region will be ignored")
    parser.add_argument('-f', '--from', dest="start_region", metavar="<Search region>", help="Where to look")
    
    args = parser.parse_args(gdb.string_to_argv(arg))

    # Step 1: --chain and --leaks can both be provided
    if args.chain and args.leaks:
      PtrFind.print_error("both --leaks and --chain were provided, please provide only one of them")
      return

    try:
      if self.proc_mapping is None:
        self.proc_mapping = PtrFind.create_proc_map()
    except gdb.error as e:
      PtrFind.print_error("Couldn't get process map. Is no program running?")
      return

    # Step 2: parse destination region
    try:
      destination = self.parse_addr_region(args.find_region)
    except SyntaxError:
      PtrFind.print_error("Failed to parse destination range")
      return
    
        
    # Step 3: parse from
    start = None
    if args.start_region is not None:
      try:
        start = self.parse_addr_region(args.start_region)
      except SyntaxError:
        PtrFind.print_error("Failed to parse from-range")
        return
    

    # Step 4: parse mode
    if args.chain:
       print("Leak-chains active")
    elif args.leaks:
      PtrFind.find_pointers(destination, self.proc_mapping)
    elif start is None: # from anywhere to ...
      PtrFind.find_pointers(self.proc_mapping, destination)
    else: # from ... to ...
      PtrFind.find_pointers(start, destination)


  def pretty_print_addr(addr, addr_region):
    '''Returns the name of the region. If the address in that region has a debug symbol, attach the name to it'''
    symbol = gdb.execute(f"info symbol {hex(addr)}", to_string=True)
    result = PtrFind.COLOR_BOLD + hex(addr) + PtrFind.COLOR_RESET + f" ({PtrFind.COLOR_BOLD + addr_region.name + PtrFind.COLOR_RESET}"
    if not symbol.startswith("No symbol"):
      # We have a symbol
      symbol = symbol.split(" ", 3) 
      result += f", {PtrFind.COLOR_WARNING + symbol[0] + PtrFind.COLOR_RESET}{('+' + hex(int(symbol[2]))) if symbol[1] == '+' else ''}"
    result += ")"
    return result


  def find_pointers(search_range, proc_mapping):
    '''Iterates over the serach range to find pointers to specific regions specified in the proc_mapping array'''
    for region in search_range:
      for addr in range(region.start, region.end, 8):
          try:
            val = PtrFind.deref(addr)
          except gdb.MemoryError:
            PtrFind.print_error(f"Unable to access value at {hex(addr)}")
          
          val_region = PtrFind.get_region(proc_mapping, val)
          if val_region is not None:
            PtrFind.print_msg(f"Pointer to {PtrFind.COLOR_BOLD + val_region.name + PtrFind.COLOR_RESET} found at {PtrFind.pretty_print_addr(addr, region)}")


  def get_region(proc_mapping, addr, binary_search=True):
    '''Returns the region that this address belongs to. Returns None if it does not belong to any
      2 Versions that are similar in speed 
      TODO: more benchmarking
    '''
    if binary_search:
      start_index = 0
      end_index = len(proc_mapping) - 1
      while True:
        if start_index == end_index or start_index + 1 == end_index:
          break
        # addr cannot be in that range
        if addr < proc_mapping[start_index].start or addr >= proc_mapping[end_index].end:
          return None
        else:
          # Take the middle. If it is an even number, take the righter objfile
          middle_index = start_index + end_index >> 1
          if(addr >= proc_mapping[middle_index].start):
            start_index = middle_index
          else:
            end_index = middle_index
          continue
    
      # Only two items left, does the second item match?
      if start_index != end_index and addr >= proc_mapping[end_index].start and addr < proc_mapping[end_index].end:
        return proc_mapping[end_index]

      # Only one item left, so it must match
      if addr >= proc_mapping[start_index].start and addr < proc_mapping[start_index].end:
        return proc_mapping[start_index]
      else:
        return None
    else:  
      # Just iterate over the proc_mapping
      if addr >= proc_mapping[0].start and addr < proc_mapping[len(proc_mapping)-1].end:
        for m in proc_mapping:
          if addr < m.end and addr >= m.start:
                return m
      return None


  def deref(addr):
    '''Returns the value at the provided address, or throws a gdb.MemoryError if the address is invalid'''
    if type(addr) is not gdb.Value:
      addr = gdb.Value(addr)
    # I don't know why - but the gdb.MemoryError is only thrown when the resulting value is actually used
    # So, we add 0 to it. This causes the gdb.MemoryError to be thrown in here
    return addr.cast(addr.type.pointer()).referenced_value().const_value() + 0
  
  def read_integer(self, addr, size=0):
    '''Returns an unsigned integer stored at addr'''
    if size == 0: # arch default size
      size = self.pointer_size
    mem = self.memory_dump(addr, size)

    unpack = None
    if size == 8:
      unpack = u64
    elif size == 4:
      unpack = u32
    elif size == 2:
      unpack = u16
    else:
      raise ValueError("Invalid size")
    
    return unpack(mem)
  
  def memory_dump(self, addr, length):
    return gdb.selected_inferior().read_memory(addr, length).tobytes()

  def parse_addr_region(self, destination):     
    '''Receives a user-provided region string and returns a subset of the proc_mapping that represents the search region'''
    destination_start = 0
    destination_end = 0
    if destination in ["heap", "stack", "libc", "image"]:      
      for objfile in self.proc_mapping:
        if destination == "libc" and "libc.so" in objfile.name \
            or destination == "heap" and objfile.name == "[heap]" \
            or destination == "stack" and objfile.name == "[stack]" \
            or destination == "image" and objfile.name == gdb.current_progspace().filename:
          return [objfile]
      PtrFind.print_error("Failed to find region, please use address ranges manually")
      raise SyntaxError()
    elif destination == "tls":
      frame = gdb.newest_frame()
      if frame.architecture().name() != "i386:x86-64":
        PtrFind.print_error(f"TLS is currently only supported on x86-64 (found {frame.architecture().name()}), please use manual address ranges")
        raise SyntaxError()
      
      fs_base = frame.read_register("fs_base").const_value()
      try:
        val = PtrFind.deref(fs_base)
      except gdb.MemoryError:
        PtrFind.print_error("Failed to find TLS. Reason: $fs_base points to an invalid address. Please use manual address ranges")
        raise SyntaxError

      if val != fs_base:
        PtrFind.print_warning("TLS parsing might have failed, proceed with caution. Reason: Start of TLS does not contain a self-reference")
      
      tls = self.get_region(fs_base)
      tls.name = "[tls]"
      return [tls]
    elif destination.count('-') == 1: # start-end
      destination = destination.split("-")
      destination_start = int(destination[0], 0)
      destination_end = int(destination[1], 0)
    elif destination.count('+') == 1: # address+size
      destination = destination.split("+")
      destination_start = int(destination[0], 0)
      destination_end = destination_start + int(destination[1], 0)
    else:
      # Last case: This is the exact name of an objfile mapped in the current program
      # e.g. "/usr/lib64/ld-linux-x86-64.so.2" and "ld-linux-x86-64.so.2" will both work.
      for objfile in self.proc_mapping:
        if destination == objfile.name or ('/' in objfile.name and destination == objfile.name.rsplit('/', 1)[1]):
          return [objfile]
        
      # Well, tough luck I guess
      raise SyntaxError()

    # We land here if we provided an address range
    # We'll now fake a proc_mapping that contains just the segments inside the user provided range



    def in_range(region): # if the region is fully inside the range, starting inside the range, or ending inside the range. Also, the range might be inside the region
      return (destination_start <= region.start and destination_end >= region.end) or \
      (destination_end > region.start and destination_end < region.end) or \
      (destination_start >= region.start and destination_start <= region.end) or \
      (destination_start >= region.start and destination_end <= region.end)

        
    destination_mapping = list(filter(in_range, copy.deepcopy(proc_mapping)))

    if(len(destination_mapping) == 0):
      PtrFind.print_error("Provided address range is unmapped")
      raise SyntaxError
 
    # cut of the contained objfiles and segments at the boundary 
    for objfile in destination_mapping:
      objfile.name = "user-defined region in " + objfile.name
      objfile.segments = list(filter(in_range, objfile.segments))
      objfile.segments[0].start = destination_start
      objfile.segments[len(objfile.segments)-1] = destination_end
    
    destination_mapping[0].start = destination_start
    destination_mapping[len(destination_mapping )-1].end = destination_end
    return destination_mapping 
    

  '''
  Manually parse the output of `i proc m` into something that we can understand

  we will return a list of strings containing objfiles
  an objfile has a name and a list of segments
  a segement has a start end size offset and permissions
  permissions have a truth values for read, write andexecute
  
  gdb builtin get objfiles/ get spaces doesn't return what we expect
  '''
  def create_proc_map():
    '''Manually parse the output of `i proc m` into something that we can understand'''
    mappings_output = gdb.execute("info proc mappings", to_string=True).splitlines()[4:]
    
    objfiles = []
    current_objfile = None
    
    for line in mappings_output:
      line_entries = list(filter(lambda x: x != '' and x != '\t' , line.split(" ")))

      segment = SimpleNamespace(
        start = int(line_entries[0],16),
        end = int(line_entries[1],16),
        #size = int(line_entries[2],16),
        offset = int(line_entries[3],16),
        perissions = PtrFind.parse_page_permissions(line_entries[4])
      )

      # new objfile
      if segment.offset == 0:
        if current_objfile is not None:
          objfiles.append(current_objfile)
        
        new_name = ''
        if len(line_entries) == 6:
          new_name = line_entries[5]

        current_objfile = SimpleNamespace(
          name=new_name,
          segments=[],
          start = segment.start,
          end = segment.end
        )
      
      if current_objfile.name == "":
        current_objfile.name = f"[{hex(current_objfile.start)}-{hex(current_objfile.end)}]"
      current_objfile.end = segment.end
      current_objfile.segments.append(segment)
    return objfiles
    
  def parse_page_permissions(prems_str):
    return SimpleNamespace(
      read = prems_str[0] == 'r',
      write = prems_str[1] == 'w',
      execute = prems_str[2] == 'x'
    )  
    
    


PtrFind ()