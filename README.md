### EmbeddedExecutable
Loads an Executable from a byte array in Memory
The Executable does not need to be present in the File System

Could also be used to Load the Executable in the Address Space of Another Process (The Executable will not be present in ProcessList and will run under the Process Name of the Victim Process (Could be used to bypass a few AntiVirus and AntiCheats since they usually check for manual map DLLs not EXEs))

In Conclusion, we basically manual map an Executable
