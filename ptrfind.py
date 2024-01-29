try:
    import gdb 
except (ImportError, ModuleNotFoundError):
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
  i_proc_m_output = None

  special_objfiles =  ["heap", "stack", "libc", "image", "loader"]

  __doc__ = f"""
{COLOR_BOLD}{COLOR_WARNING}ptrfind{COLOR_RESET}{COLOR_BOLD} - helps you find pointers in your binary{COLOR_RESET}
{COLOR_BOLD}Simple usage:{COLOR_RESET} ptrfind <target region> [-f/--from <start region>]

{COLOR_BOLD}Options:{COLOR_RESET}
  {COLOR_BOLD}<target region> / <start region>{COLOR_RESET}
    a memory region. This can either be")
      - a name of a special region (one of {special_objfiles + ['tls']})
      - a name of a mapped objfile with or without its path (e.g. \"/usr/lib64/ld-linux-x86-64.so.2\" and \"ld-linux-x86-64.so.2\" will both work.)
      - a start and end address separated by a minus, e.g. 0x7ffff7fa7000-0x7ffff7fa9000
      - a start address and size separated by a plus, e.g. 0x7ffff7fa7000+0x2000
  {COLOR_BOLD}-f / --from <start region>{COLOR_RESET}
    Where to start looking for pointers
  {COLOR_BOLD}--chain <#chains printed>{COLOR_RESET}
    Print leak-chains, with the optional argument specifying how many chains are printed (default: 5)

{COLOR_BOLD}Advanced options:{COLOR_RESET}
  {COLOR_BOLD}-a / --all{COLOR_RESET}
    Print all pointers for a region instead of just the first five
  {COLOR_BOLD}-b / --bad-bytes{COLOR_RESET}
    A comma-separated list of hex-values that are not allowed to be in the pointer (e.g. \"00,0a\")
  {COLOR_BOLD}-c / --cache-all{COLOR_RESET}
    Also cache the pointers found in writeable sections (faster, but may lead to wrong/incomplete output down the line)
  {COLOR_BOLD}--clear-cache{COLOR_RESET}
    Clear the entire cache and re-fetch the process map

{COLOR_BOLD}Examples:{COLOR_RESET}
  {COLOR_BOLD}ptrfind libc -a{COLOR_RESET}
    Print all pointers to the libc found in any memory region
  {COLOR_BOLD}ptrfind libc --from image{COLOR_RESET}
    Print 5 pointers from image to the libc
  {COLOR_BOLD}ptrfind --from image{COLOR_RESET}
    Print 5 pointers found in the image-region
  {COLOR_BOLD}ptrfind tls --from image --chain 10 -b 00{COLOR_RESET}
    Print the 10 shortest leak-chains from the image-region to the tls that don't contain NULL-Bytes in their pointers
  {COLOR_BOLD}ptrfind 0x7ffff7dc8000-0x7ffff7dd6000 --from libtinfo.so.6.4{COLOR_RESET}
    Print 5 pointers from the given memory region to the tinfo library
  """

  def __init__ (self):
    super (PtrFind, self).__init__ ("ptrfind", gdb.COMMAND_USER)

  def print_msg(msg):
    print(PtrFind.COLOR_OK + PtrFind.COLOR_BOLD + "[+] " + PtrFind.COLOR_RESET + msg)

  def print_error(msg):
    print(PtrFind.COLOR_FAIL + PtrFind.COLOR_BOLD + "[-] " + PtrFind.COLOR_RESET + msg)

  def print_warning(msg):
    print(PtrFind.COLOR_WARNING + PtrFind.COLOR_BOLD + "[!] " + PtrFind.COLOR_RESET + msg)

  def objfile_to_id(objfile): return objfile.id
  
  def contains_bad_bytes(val,bad_bytes):
    if bad_bytes is None:
      return False
    for byte in struct.pack("Q", val).rstrip(b"\x00"):
      if byte in bad_bytes:
        return True
    return False

  def invoke (self, arg, from_tty):
    parser = argparse.ArgumentParser(
                    prog='ptrfind',
                    description='Helps you find pointers in your program.',
                    add_help=False)
    parser.add_argument('find_region', metavar="<destination region>", nargs="?")
    parser.add_argument('--chain', nargs="?", const=5, type=int)
    parser.add_argument('-f', '--from', dest="start_region", metavar="<Search region>")
    parser.add_argument('-a', "--all", action='store_true')
    parser.add_argument('-c', "--cache-all", action='store_true')
    parser.add_argument('-b', "--bad-bytes")
    parser.add_argument('-h', "--help", action="store_true")
    parser.add_argument("--clear-cache", action='store_true')
    
    args = None
    try:
      args = parser.parse_args(gdb.string_to_argv(arg))
    except Exception:
      PtrFind.print_error(f"Option parsing failed")
      return
    
    self.pointer_size = gdb.lookup_type('void').pointer().sizeof
    self.little_endian = "little endian" in gdb.execute("show endian", to_string=True)

    if args.help:
      print(self.__doc__)
      return

    if self.proc_mapping is not None and self.i_proc_m_output != gdb.execute("info proc mappings", to_string=True):
      PtrFind.print_warning("the process map was updated (e.g. new permissions, new pages mapped). Cache has been cleared.")
      self.proc_mapping = None
    
    if args.clear_cache:
      self.proc_mapping = None
      PtrFind.print_msg("Cache has been cleared")

    # Step 1: If the cache is empty, create a proc mapping
    try:
      if self.proc_mapping is None:
        self.create_proc_map()
    except gdb.error as e:
      PtrFind.print_error("Couldn't get process map. Is no program running?")
      return

    # Step 2: parse destination region
    destination = None
    if args.find_region is not None:
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

    
    # Step 4: Parse bad bytes
    if args.bad_bytes is not None:
      args.bad_bytes = args.bad_bytes.split(",")
      args.bad_bytes = list(map(lambda hexstr: int("0x"+hexstr, 16) & 0xFF, args.bad_bytes))

    def is_valid_pointer(addr, val, from_start, to_end):
      '''A function that is called to check if a pointer fits our criteria (in start region, in end region, has bad byte)'''
      # Is there a bad byte?
      if PtrFind.contains_bad_bytes(val,args.bad_bytes):
        return False

      # Is it contained in the start region?
      if from_start:
        contained = False  
        for objfile in start:
          if addr >= objfile.start and addr < objfile.end:
            contained = True
        
        if not contained:
          return False
      # Is it contained in the end region?    
      if to_end:
        contained = False
        for objfile in destination:
          if val >= objfile.start and val < objfile.end:
            contained = True
        
        if not contained:
          return False
      # Seems to be fine(TM)
      return True

    # Step 5: parse mode
    if args.chain:
      # Leak chains
      if start is None:
        PtrFind.print_error("-f/--from is missing")
        return
      PtrFind.print_msg("Searching for leak-chains, this may take a few minutes")
      leak_chains = self.find_pointer_chains(list(map(PtrFind.objfile_to_id, start)), list(map(PtrFind.objfile_to_id, destination)), is_valid_pointer)
      self.print_leak_chains(leak_chains, args.all, args.bad_bytes, args.chain)
    else:
      # Searching for pointers
      searched_regions = None
      destination_regions = None
      if start is not None and destination is None: # from .. to anywhere
        searched_regions = start
        destination_regions = self.proc_mapping
      elif start is None and destination is not None: # from anywhere to ...
        searched_regions = self.proc_mapping
        destination_regions = destination
      elif start is not None and destination is not None: # from ... to ...
        searched_regions = start
        destination_regions = destination
      else:
        PtrFind.print_error("Missing start and/or destination range")
        return

      PtrFind.print_msg("Searching for pointers, this may take a few minutes")
      
      # Fill the cache of those regions
      memory_errors = self.find_pointers(list(map(PtrFind.objfile_to_id, searched_regions)))

      # Now, go through the caches
      self.print_pointers(searched_regions, destination_regions, args.all, args.bad_bytes)
      
      if memory_errors > 0:
        PtrFind.print_error(f"{memory_errors} {'address' if memory_errors == 1 else 'addresses'} could not be accessed due to a memory error.")

    # Clear the cache for writeable pages
    if not args.cache_all:
      for objfile in self.proc_mapping:
        for segment in objfile.segments:
          if segment.permissions.write:
            segment.cache = None


  def print_pointers(self, searched_regions, destination_regions, print_all, bad_bytes, verbose_print=True):
    '''Print the result of a pointer search'''
    total_pointers = 0
    # Go through all searched regions
    for i in range(0, len(searched_regions)):
        id = searched_regions[i].id
        objfile = self.proc_mapping[id]
        # Check the cache of the destinations we are looking for
        for destination in destination_regions:
          # A counter to determine how many pointers we found
          ptrs_printed = 0
          # Check the cache of each segment
          for segment in objfile.segments:
            destination_id = destination.id
            # Go through every pointer. We need to check some conditions first
            for(address, value, symbol_src, symbol_dest) in segment.cache[destination_id]:
              # 1. The value mustn't contain any bad byte
              if PtrFind.contains_bad_bytes(value, bad_bytes):
                continue    
              
              # 2. The address must be in our source range
              # 3. The value must be in our destination range
              if address >= searched_regions[i].start and address < searched_regions[i].end and \
                 value >= destination.start and value < destination.end:
                if ptrs_printed == 0 and verbose_print:
                  PtrFind.print_msg(f"Pointer(s) found from {PtrFind.COLOR_BOLD}{searched_regions[i].name}{PtrFind.COLOR_RESET} to {PtrFind.COLOR_BOLD}{destination.name}{PtrFind.COLOR_RESET}:")
                # a maximum of 5 pointers will be printed
                if ptrs_printed < 5 or print_all:
                  print(f"\t{PtrFind.COLOR_BOLD}{hex(address)}{PtrFind.COLOR_RESET}{symbol_src} → {hex(value)}{symbol_dest}")
                ptrs_printed += 1
          # Inform the user if we omitted pointers
          if ptrs_printed > 5:
            print(f"\t({ptrs_printed - 5} pointer{'s' if ptrs_printed > 6 else ''} omitted, use -a to show all)")
          total_pointers += ptrs_printed

    if verbose_print:   
      if total_pointers == 0:
        PtrFind.print_error(f"Search done, no pointers were found")
      else:
        # Flex with our findings on stdout
        PtrFind.print_msg(f"Search done, {total_pointers} pointer{'' if total_pointers == 1 else 's'} found")
      

  def print_leak_chains(self, leak_chains, print_all, bad_bytes, max_chains_printed):
    '''Receives the result of a leak-chain search, and prints them'''
    # First, sort by the number of leaks required. The shorter, the better
    leak_chains.sort(key=lambda x: len(x))
    # No chains? :(
    if leak_chains == []:
      PtrFind.print_error(f"Search done, no paths were found")
    else:
      num_chains = 0
      for chain in leak_chains:
        if num_chains >= max_chains_printed:
          PtrFind.print_msg(f"{len(leak_chains) - num_chains} more chains were found but not printed, use --chain <num_chains_printed> to show more")
          break
        PtrFind.print_msg(f"Leak-chain found ({len(chain) -1} leak{'s' if len(chain) > 2 else ''}):")
        # Here, we have a list of ids where we step through
        for i in range(0, len(chain)):
          id = chain[i]
          print(f"  → {self.proc_mapping[id].name}")
          # If it is not the final step, print the pointers that go into the next section
          if i != len(chain) - 1:
            self.print_pointers([self.proc_mapping[id]], [(self.proc_mapping[chain[i + 1]])], print_all, bad_bytes, verbose_print=False)
        num_chains += 1
      PtrFind.print_msg(f"Search done, {len(leak_chains)} unique chain{'s were' if len(leak_chains) > 1 else ' was'} found")

  
  def find_pointer_chains_rec(self, search_region_index, destination_range, visited, is_valid_pointer : list[int]) -> list[list[int]]:
    '''A recursive helper for find_pointer_chains'''
    search_region = self.proc_mapping[search_region_index]

    new_visited = visited + [search_region_index]
    chains = []

    # create cache for current search region, if not done already
    self.find_pointers([search_region_index])

    # for every possible next region
    for next_region_index in range(0,len(self.proc_mapping)):
      # do nothing if region is irrelevant (loop/ relflexive pointer)
      if (next_region_index == search_region_index or next_region_index in new_visited ):
        continue
      # check if we can get to the target region (including bounds check on start and end)
      path_exists = False
      points_to_end = (next_region_index in destination_range)
      from_start = (visited == [])
      for search_segment in search_region.segments:
        pointers = search_segment.cache[next_region_index]
        if pointers != [] and not path_exists:            
          valid_found = False
          for (addr, val, _, _) in pointers:
            if is_valid_pointer(addr, val, from_start, points_to_end):
              valid_found = True
              break

          path_exists = valid_found

      if not path_exists:
        continue # can't get to the target
      elif points_to_end:
        chains += [[search_region_index,next_region_index]] # reached our destination
      else:
        # take a step and continue looking for chains from that region
        chains += list(map(
          lambda chain: [search_region_index] + chain,
          self.find_pointer_chains_rec(next_region_index,destination_range,new_visited, is_valid_pointer))) 

    return chains


  def find_pointer_chains(self, search_range: list[int], destination_range:list[int], is_valid_pointer) -> list[list[int]]:
    chains = []
    for region_id in search_range:
      chains += self.find_pointer_chains_rec(region_id, destination_range, [], is_valid_pointer)
    return chains


  def get_symbol(address):
    '''Returns a string representing the debug symbol at said address, or an empty String if there is no symbol'''
    symbol = gdb.execute(f"info symbol {hex(address)}", to_string=True)
    if not symbol.startswith("No symbol"):
      # We have a symbol
      symbol = symbol.split(" ", 3) 
      offset = '+' + hex(int(symbol[2])) if symbol[1] == '+' else ""
      return f" ({PtrFind.COLOR_WARNING}{symbol[0]}{offset}{PtrFind.COLOR_RESET})"
    else:
      return ""


  def find_pointers(self, ids_to_scan):
    '''Receives an array of section id's (aka. indexes) and fills their caches by scanning their memory and looking for pointers. If a cache is not empty, it is skipped'''
    memory_errors = 0
    # For every id
    for id in ids_to_scan:
      objfile = self.proc_mapping[id]
      # For each segment in said objfile
      for segment in objfile.segments:
        # The cache is already filled => skip to the next one
        if segment.cache is not None:
          continue

        # Initialise the cache with empty arrays
        segment.cache = []
        for i in range(0, len(self.proc_mapping)):
          segment.cache.append([])
        
        # Now, walk through the entire memory
        for address in range(segment.start, segment.end, self.pointer_size):
          try:
            val = self.deref(address)
          except gdb.MemoryError:
            memory_errors += 1
            continue
            
          # This call returns the region index in the proc_mapping, or None if the value is not a pointer
          region_index = PtrFind.get_region(self.proc_mapping, val)
          if region_index is not None:
            # We found a pointer! cache it
            segment.cache[region_index].append((address, val, PtrFind.get_symbol(address), PtrFind.get_symbol(val)))
    return memory_errors


  def verify_caches(self):
    '''Used for debugging this extension only, should(TM) not be relevant in "production"'''
    if self.proc_mapping is None:
      return
    for objfile in self.proc_mapping:
      for segment in objfile.segments:
        if segment.cache is None:
          continue
        for i in range(0, len(segment.cache)):
          for (addr, val, _, _) in segment.cache[i]:
            if addr < segment.start or addr >= segment.end or val < self.proc_mapping[i].start or val >= self.proc_mapping[i].end:
              raise SyntaxError("Broken cache found!")  
    PtrFind.print_msg("Cache verified!")  
  

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
  
  def memory_dump(addr, length):
    return gdb.selected_inferior().read_memory(addr, length).tobytes()

  def parse_addr_region(self, destination):     
    '''Receives a user-provided region string and returns a subset of the proc_mapping that represents the search region'''
    destination_start = 0
    destination_end = 0
    # There are some magic keywords that one can use to automatically get the objfile
    if destination in self.special_objfiles:      
      for objfile in self.proc_mapping:
        if destination == "libc" and (("libc-" in objfile.name and ".so" in objfile.name) or "libc.so" in objfile.name) \
            or destination == "loader" and (("ld-" in objfile.name and ".so") or "ld.so" in objfile.name) \
            or destination == "heap" and objfile.name == "[heap]" \
            or destination == "stack" and objfile.name == "[stack]" \
            or destination == "image" and objfile.name == gdb.current_progspace().filename:
          return [objfile]
      PtrFind.print_error("Failed to find region, please use address ranges manually")
      raise SyntaxError()
    # "tls" requires extra handling, so it is in an extra if-clause
    elif destination == "tls":
      # Our tls detection only works on x86-64
      frame = gdb.newest_frame()
      if frame.architecture().name() != "i386:x86-64":
        PtrFind.print_error(f"TLS is currently only supported on x86-64 (found {frame.architecture().name()}), please use manual address ranges")
        raise SyntaxError()
      
      # Oh and it only works if $fs_base is used as the tls base
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
      tls.name = f"[tls] ({hex(tls.start)}-{hex(tls.end)})"
      return [tls]
    
    # Possiblity: This is the exact name of an objfile mapped in the current program
    # e.g. "/usr/lib64/ld-linux-x86-64.so.2" and "ld-linux-x86-64.so.2" will both work.
    for objfile in self.proc_mapping:
      if destination == objfile.name or ('/' in objfile.name and destination == objfile.name.rsplit('/', 1)[1]):
        return [objfile]

    # Memory range with start-end
    if destination.count('-') == 1:
      destination = destination.split("-")
      try:
        destination_start = int(destination[0], 0)
        destination_end = int(destination[1], 0)
      except Exception as e:
        PtrFind.print_error(f"Failed to parse memory range: {e}")
        raise SyntaxError()
    # Memory range with start+size
    elif destination.count('+') == 1:
      destination = destination.split("+")
      try:
        destination_start = int(destination[0], 0)
        destination_end = destination_start + int(destination[1], 0)
      except Exception as e:
        PtrFind.print_error(f"Failed to parse memory range: {e}")
        raise SyntaxError()
    else:
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
      PtrFind.print_error("Provided address range is completely unmapped")
      raise SyntaxError
 
    # Change the name
    for objfile in destination_mapping:
      objfile.name = "user-defined region in " + objfile.name    
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
  def create_proc_map(self):
    '''Manually parse the output of `i proc m` into something that we can understand'''
    self.i_proc_m_output = gdb.execute("info proc mappings", to_string=True)
    mappings_output = self.i_proc_m_output.splitlines()[4:]
    
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
    self.proc_mapping = objfiles
    
  def parse_page_permissions(prems_str):
    return SimpleNamespace(
      read = prems_str[0] == 'r',
      write = prems_str[1] == 'w',
      execute = prems_str[2] == 'x'
    )  
    
    


PtrFind ()
