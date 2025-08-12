# Note
The patcher has the public key hardcoded - if you are 100% sure the public key is different from what is hardcoded in the script, you can either change it in the script itself or change it in the configuration file post-generation.<br>
Open an issue ticket rather than contacting me directly if you have any problems.<br><br>
**To use the program, just open server.bat**

# Requirements
Python (Preferably 3.9 or newer)<br>
Optional requirement: Renamed x64dbg with ScyllaHide plugin<br>
Optional requirement: Renamed Cheat Engine<br>

# Miscellaneous
### Video/Showcase
https://youtu.be/TL1ID4sbU1M - Showcase/Tutorial #1<br>
https://youtu.be/xSofBJGAfTQ - Showcase/Tutorial #2

### Finding pubkey (OPTIONAL)
Open the x64dbg folder and rename x64dbg.exe to anything else
Open x64dbg, go to Options -> Preferences and toggle the "Exit Breakpoint"<br>
Attach to your desired process<br>
Right click inside the disassembler -> Search for -> All modules -> String references<br>
Press the regex toggle on the bottom right<br>
Put in the following regex: `[a-zA-Z0-9]{64}`<br>
Find what seems to be your public key (e.g. "f7ab43f1cc6907bbb66d77bc0eadbfdbd0f108710d3a52b88750ad205158f64c")<br>
Right click -> Copy -> String , save it in your notepad.<br>
Copy just the public key string<br>
Run server.py, run patcher.py, put the found public key inside. That's it<br>

### LegacyPatch -- Patching via offset rather than memory scanner (OPTIONAL)
Open your Cheat Engine (do not detach x64dbg yet)<br>
Attach to your process<br>
Select "Value Type" -> "String"<br>
Find the `ProcessName.exe+OFFSET` value<br>
Right click the address and press "Copy selected address" (e.g. `ProcName.exe+2F3170`)<br>
Terminate the program via x64dbg and close both the debugger and Cheat Engine as we no longer need it.<br>
Start server.bat and put in the values (For offset you would want to do `0x2F3170`, make sure your pasted values do not have quotation marks)
