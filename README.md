# ace-proctree

Create a simple process tree like https://twitter.com/ACEResponder.

Export a CSV from your SIEM with the following headers: process_name, pid, ppid.
It will use the first row as the root process and move down the tree by searching for ppids.
No need to groom the output, it will simply ignore unrelated processes.

| process_name |      pid     |     ppid      |
|--------------|--------------|---------------|
| C:\\first.exe |     1000     |     500       |
| C:\\2nd.exe   |     1001     |     1000      |

![](https://assets.aceresponder.com/meta/ace-proctree.png)
