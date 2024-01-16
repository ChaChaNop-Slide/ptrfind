try:
    import gdb 
except ImportError:
    print("[-] This command cannot run as standalone. See README for details.")
    exit(1)

import argparse

class PtrFind (gdb.Command):
  def __init__ (self):
    super (PtrFind, self).__init__ ("ptrfind", gdb.COMMAND_USER)

  def invoke (self, arg, from_tty):
    print ("Hello, World!")
    parser = argparse.ArgumentParser(
                    prog='ptrfind',
                    description='Helps you find pointers in your program.',
                    epilog="""TODO: Explanation of address format\n
                    For more information, check [insert repo url here]""")
    parser.add_argument('find_region', metavar="<destination region>")
    parser.add_argument('--chain', action='store_true', help="enables leak-chains")
    parser.add_argument('--leaks', action='store_true', help="look for outgoing leaks in the provided section. The destination region will be ignored")
    parser.add_argument('-f', '--from', metavar="<Search region>", help="Where to look")

    
    args = parser.parse_args(gdb.string_to_argv(arg))
    

PtrFind ()