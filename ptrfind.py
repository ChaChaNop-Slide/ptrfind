try:
    import gdb 
except ImportError:
    print("[-] This command cannot run as standalone. See README for details.")
    exit(1)

import argparse
from types import SimpleNamespace
import copy
import time

class PtrFind (gdb.Command):
  COLOR_OK = "\033[92m"  # GREEN
  COLOR_WARNING = "\033[93m"  # YELLOW
  COLOR_FAIL = "\033[91m"  # RED
  COLOR_BOLD = "\033[1m"
  COLOR_RESET = "\033[0m"

  little_endian = None
  pointer_size = None
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
    parser.add_argument('-a', "--all", action='store_true', help="print all pointers instead of only the first matches")
    parser.add_argument('-c', "--cache-all", action='store_true', help="also cache the pointers found in writeable sections (faster, but may lead to wrong/incomplete output)")
    
    args = parser.parse_args(gdb.string_to_argv(arg))
    self.pointer_size = gdb.lookup_type('void').pointer().sizeof
    self.little_endian = "little endian" in gdb.execute("show endian", to_string=True)

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
    
    '''
    t1_start = time.perf_counter() 
    self.find_pointers_efficient(start)
    t1_stop = time.perf_counter()
    print("Elapsed efficient time in seconds:",t1_stop-t1_start)
    '''

    def objfile_to_id(objfile): return objfile.id

    memory_errors = 0
    # Step 4: parse mode
    if args.chain:
       print("Leak-chains active")
       print(self.find_pointer_chains(list(map(objfile_to_id, start)), list(map(objfile_to_id, destination))))
    else:
      searched_regions = None
      destination_regions = None
      if args.leaks: # from .. to anywhere
        searched_regions = destination
        destination_regions = self.proc_mapping
      elif start is None: # from anywhere to ...
        searched_regions = self.proc_mapping
        destination_regions = destination
      else: # from ... to ...
        searched_regions = start
        destination_regions = destination

      PtrFind.print_msg("Searching for pointers, this may take a few minutes")
      
      # Fill the cache of those regions
      memory_errors = self.find_pointers(list(map(objfile_to_id, searched_regions)))

      # Now, go through the caches
      self.print_pointers(searched_regions, destination_regions, args.all)
      
      if memory_errors > 0:
        PtrFind.print_error(f"{memory_errors} {'address' if memory_errors == 1 else 'addresses'} could not be accessed due to a memory error.")

    # Clear the cache for writeable pages
    if not args.cache_all:
      for objfile in self.proc_mapping:
        for segment in objfile.segments:
          if segment.permissions.write:
            segment.cache = None

  def print_pointers(self, searched_regions, destination_regions, print_all):
    '''Print the result of a pointer search'''
    total_pointers = 0
    for i in range(0, len(searched_regions)):
        id = searched_regions[i].id
        objfile = self.proc_mapping[id]
        # Check the cache of each segment
        for segment in objfile.segments:
          # Check the cache of the destinations we are looking for
          for destination in destination_regions:
            # A counter to determine how many more pointers will be printed
            ptrs_printed = 0
            ptrs_omitted = 0
            destination_id = destination.id
            for(address, value, symbol) in segment.cache[destination_id]:
              # 1. The address must be in our source range
              # 2. The value must be in our destination range
              if address >= searched_regions[i].start and address < searched_regions[i].end and \
                 value >= destination.start and value < destination.end:
                if ptrs_printed == 0:
                  PtrFind.print_msg(f"Pointer(s) found from {PtrFind.COLOR_BOLD}{searched_regions[i].name}{PtrFind.COLOR_RESET} to {PtrFind.COLOR_BOLD}{destination.name}{PtrFind.COLOR_RESET}:")
                if ptrs_printed < 5 or print_all:
                  print(f"\t{PtrFind.COLOR_BOLD}{hex(address)}{PtrFind.COLOR_RESET}{f' ({PtrFind.COLOR_WARNING}{symbol}{PtrFind.COLOR_RESET})' if symbol is not None else ''} → {hex(value)}")
                  ptrs_printed += 1
                else:
                  ptrs_omitted += 1
            if ptrs_omitted > 0:
              print(f"\t({ptrs_omitted} pointer{'s' if ptrs_omitted > 1 else ''} omitted, use -a to show all)")
            total_pointers += ptrs_printed + ptrs_omitted
               
    if total_pointers == 0:
      PtrFind.print_error(f"Search done, no pointers were found")
    else:
      PtrFind.print_msg(f"Search done, {total_pointers} pointer{'' if total_pointers == 1 else 's'} found")


  def print_leak_chains(leak_chains):
    if leak_chains == []:
      PtrFind.print_error(f"Search done, no chains were found")
    else:
      for chain in leak_chains:
          break




  # return a list of list chains per region
  # a chain is a list of step from region to another region
  # represented by a list of pointers
  # a pointer is represented by a tuple of region,
  
  def find_pointer_chains_rec(self, search_region_index, destination_range, visited):
    search_region = self.proc_mapping[search_region_index]
    new_visited = visited + [search_region_index]
    chains = []

    #update cache for current search region
    self.find_pointers([search_region_index])

    # for every possible target region check if we can get there
    for target_region_index in range(0,len(self.proc_mapping)):
        #  3. we can't get there 
      
      
      # we can ignore the possible target if
      #  1. we point back to where we are right now
      #  2. we've been there already (loop)
      irrelevant_region = target_region_index == search_region_index \
        or target_region_index in visited 
      
      if not irrelevant_region:

        for search_segment in search_region.segments:
          pointers = search_segment.cache[target_region_index]

          if target_region_index in destination_range:
            # we've made it to out target so we can get there in 0 steps
            new_chains = [pointers]
          elif not pointers == []:
            # we've made it to a new region lets see where we can get from there
            new_chains = list(map(
              lambda chain: [pointers] + chain,self.find_pointer_chains_rec(target_region_index,
              destination_range,new_visited)))
          else:
            new_chains = []

          chains += new_chains

        
    return chains


  def find_pointer_chains(self, search_range, destination_range):
    chains = []
    for region in search_range:
      chains += self.find_pointer_chains_rec(region, destination_range, [])
    return chains


  def get_symbol(address):
    symbol = gdb.execute(f"info symbol {hex(address)}", to_string=True)
    if not symbol.startswith("No symbol"):
      # We have a symbol
      symbol = symbol.split(" ", 3) 
      if symbol[1] == '+': # with offset
        return f"{symbol[0]}+{hex(int(symbol[2]))}"
      else:
        return symbol[0]
    else:
      return None

  '''
  Fun Fact: Dumping the entire memory and then walking through it is slower by a factor of 6-8 on my laptop
  '''
  def find_pointers(self, ids_to_scan):
    memory_errors = 0
    for id in ids_to_scan:
      objfile = self.proc_mapping[id]
      for segment in objfile.segments:
        if segment.cache is not None:
          continue
        segment.cache = [[]] * len(self.proc_mapping)
        
        for address in range(segment.start, segment.end, self.pointer_size):
          try:
            val = self.deref(address)
          except gdb.MemoryError:
            memory_errors += 1
            continue
          region_index = PtrFind.get_region(self.proc_mapping, val)
          if region_index is not None:
            # We found a pointer! cache it
            segment.cache[region_index].append((address, val, PtrFind.get_symbol(address)))
    return memory_errors
        
  
  '''
  def find_pointers(search_range, proc_mapping):
    #Iterates over the serach range to find pointers to specific regions specified in the proc_mapping array
    for region in search_range:
      for addr in range(region.start, region.end, 8):
          try:
            val = PtrFind.deref(addr)
          except gdb.MemoryError:
            PtrFind.print_error(f"Unable to access value at {hex(addr)}")
          
          val_region = PtrFind.get_region(proc_mapping, val)
          if val_region is not None:
            val_region = proc_mapping[val_region]
            PtrFind.print_msg(f"Pointer to {PtrFind.COLOR_BOLD + val_region.name + PtrFind.COLOR_RESET} found at {PtrFind.pretty_print_addr(addr, region)}")
  '''

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
        return end_index

      # Only one item left, so it must match
      if addr >= proc_mapping[start_index].start and addr < proc_mapping[start_index].end:
        return start_index
      else:
        return None
    else:  
      # Just iterate over the proc_mapping
      if addr >= proc_mapping[0].start and addr < proc_mapping[len(proc_mapping)-1].end:
        for i in range(0, len(proc_mapping)):
          m = proc_mapping[i]
          if addr < m.end and addr >= m.start:
                return i
      return None


  def deref(self, addr):
    '''Returns the value at the provided address, or throws a gdb.MemoryError if the address is invalid'''
    return int.from_bytes(PtrFind.memory_dump(addr, self.pointer_size), "little" if self.little_endian else "big")
  
  def read_integer(self, addr, size=0):
    '''Returns an unsigned integer stored at addr'''
    if size == 0: # arch default size
      size = self.pointer_size

    return int.from_bytes(PtrFind.memory_dump(addr, size), "little" if self.little_endian else "big")
  
  def memory_dump(addr, length):
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
        val = self.deref(fs_base)
      except gdb.MemoryError:
        PtrFind.print_error("Failed to find TLS. Reason: $fs_base points to an invalid address. Please use manual address ranges")
        raise SyntaxError

      if val != fs_base:
        PtrFind.print_warning("TLS parsing might have failed, proceed with caution. Reason: Start of TLS does not contain a self-reference")
      
      tls = PtrFind.get_region(self.proc_mapping, fs_base)
      tls = self.proc_mapping[tls]
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

        
    destination_mapping = list(filter(in_range, copy.deepcopy(self.proc_mapping)))

    if(len(destination_mapping) == 0):
      PtrFind.print_error("Provided address range is unmapped")
      raise SyntaxError
 
    # cut of the contained objfiles and segments at the boundary 
    for objfile in destination_mapping:
      objfile.name = "user-defined region in " + objfile.name
      objfile.segments = list(filter(in_range, objfile.segments))
      #objfile.segments[0].start = destination_start
      #objfile.segments[len(objfile.segments)-1] = destination_end
    
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
        permissions = PtrFind.parse_page_permissions(line_entries[4]),
        cache = None
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
          end = segment.end,
          id = len(objfiles)
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