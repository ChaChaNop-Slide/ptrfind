try:
    import gdb 
except ImportError:
    print("[-] This command cannot run as standalone. See README for details.")
    exit(1)

import argparse
from types import SimpleNamespace

class PtrFind (gdb.Command):
  def __init__ (self):
    super (PtrFind, self).__init__ ("ptrfind", gdb.COMMAND_USER)

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
      print("[-] both --leaks and --chain were provided, please provide only one of them")
      return

    # Step 2: parse destination region
    proc_mapping = PtrFind.create_proc_map()
    try:
      destination = PtrFind.parse_addr_region(proc_mapping, args.find_region)
    except SyntaxError:
      print("[-] Failed to parse destination range")
      return
    
    print(f"start: {hex(destination[0])}; end: {hex(destination[1])}")
    
    # Step 3: parse from
    start = None
    if args.start_region is not None:
      try:
        start = PtrFind.parse_addr_region(proc_mapping, args.start_region)
      except SyntaxError:
        print("[-] Failed to parse from-range")
        return
      print(f"start: {hex(start[0])}; end: {hex(start[1])}")
    else:
      print("No from provided")
    

    # Step 4: parse mode
    if args.chain:
       print("Leak-chains active")
    elif args.leaks:
       print("Leaks in a section")
    else:
       print("Normal mode")

  def parse_addr_region(proc_mapping, destination):     
    destination_start = 0
    destination_end = 0
    if destination in ["heap", "stack", "libc", "image"]:      
      for objfile in proc_mapping:
        if destination == "libc" and "libc.so" in objfile.name \
            or destination == "heap" and objfile.name == "[heap]" \
            or destination == "stack" and objfile.name == "[stack]" \
            or destination == "image" and objfile.name == gdb.current_progspace().filename:
          destination_start = objfile.segments[0].start
          destination_end = objfile.segments[len(objfile.segments) - 1].end
          return (destination_start, destination_end)
      print("[-] Failed to find region, please use address ranges manually")
      raise SyntaxError()
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
      for objfile in proc_mapping:
        if destination == objfile.name or ('/' in objfile.name and destination == objfile.name.rsplit('/', 1)[1]):
          destination_start = objfile.segments[0].start
          destination_end = objfile.segments[len(objfile.segments) - 1].end
          return (destination_start, destination_end)
        
      # Well, tough luck I guess
      raise SyntaxError()
    
    return (destination_start, destination_end)


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
      line_entries = list(filter(lambda x: x != '' , line.split(" ")))

      segment = SimpleNamespace(
        start = int(line_entries[0],16),
        end = int(line_entries[1],16),
        size = int(line_entries[2],16),
        offset = int(line_entries[3],16),
        perissions = PtrFind.parse_page_permissions(line_entries[4])
      )

      # new objfile
      if segment.offset == 0:
        if current_objfile is not None:
          objfiles.append(current_objfile)
        
        new_name = ""
        if len(line_entries)==6:
          new_name = line_entries[5]

        current_objfile = SimpleNamespace(name=new_name,segments =[] )
      
      current_objfile.segments.append(segment)
    return objfiles
    
  def parse_page_permissions(prems_str):
    return SimpleNamespace(
      read = prems_str[0] == 'r',
      write = prems_str[1] == 'w',
      execute = prems_str[2] == 'x'
    )  
    
    


PtrFind ()