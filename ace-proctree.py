#!/usr/bin/python
import os
import csv
import argparse
import re
from rich import print
from anytree import Node, PreOrderIter, RenderTree

description='''
Create a simple process tree like https://twitter.com/ACEResponder.

Export a CSV from your SIEM with the following headers: process_name, pid, ppid.
It will use the first row as the root process and move down the tree by searching for ppids.
No need to groom the output - it will simply ignore unrelated processes.

| process_name |      pid     |     ppid      |
|--------------|--------------|---------------|
| C:\\first.exe |     1000     |     500       |
| C:\\2nd.exe   |     1001     |     1000      |

Returns a tree like this:

first
│
├── 2nd
│   │
│   └── 3rd
│
└── 4th

'''

def cmdline_args():
        # Make parser object
    p = argparse.ArgumentParser(prog='ace_proctree.py', description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    p.add_argument("csv",
                   help="CSV file of processes. The root process needs to be the first row. Required columns: process_name, pid, ppid")
    p.add_argument("-f", "--fields", nargs="*", type=str,
                   help="Additional field(s) to display.")
    p.add_argument("-c", type=str, default='red', choices=['black','white','red','green','blue','magenta','cyan'],
                   help="Default color for process_name")
                   

    return(p.parse_args())


def parse_proc_tree(data, color, add_fields):
  root = Node('root')
  first = True
  for row in data:
    m = re.search(r'([^\\]+)\.[^\.]*?$',row['process_name']).group(1)
    node = Node(name=m)
    for col in row:
      #row[col] = row[col].replace('\\','\\\\')
      setattr(node, col.split('.')[-1],row[col])

    if first:
      node.parent=root
    else:
      for n in PreOrderIter(root):
        if n.name == 'root':
          continue
        if n.pid == row['ppid']:
          #n.child = node
          node.parent=n
    

    first=False

  fchild = root.children[0]
  fchild.parent=None

  print()
  for pre, _, node in RenderTree(fchild):
    #print('%s%s => %s' %(pre,node.name,node.CommandLine))
    if pre or pre=='└':
      print(pre.replace('─','').replace('└','│').replace('├','│'))
    if add_fields:
      print('%s[bold %s]%s[/bold %s] => %s' %(pre,color,node.name,color,' | '.join([getattr(node,x) for x in add_fields])))
    else:
      print('%s[bold %s]%s[/bold %s]' %(pre,color,node.name,color))
  print()

  return fchild


if __name__ == '__main__':
    args = cmdline_args()

    path = os.path.join(os.path.dirname(__file__),args.csv)
    data =[]
    with open(path) as f:
      reader = csv.DictReader(f)
      for row in reader:
        data.append(row)
    parse_proc_tree(data,args.c, args.fields)
