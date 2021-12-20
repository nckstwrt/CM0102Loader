Website: https://github.com/nckstwrt/CM0102Loader

Description
-----------
CM0102Loader is an .exe file you put in the same directory as your CM0102.exe (only guaranteed to work with a clean 3.9.68 version - as of v1.7 it will load Saturn/Tapani exes too). CM0102Loader can patch the .exe in memory and changes no other files - so there will be no permanent changes.

Options
-------
When you run CM0102Loader.exe for the first time it will create a CM0102Loader.ini file in the same directory with the following default options:

Year = 2001
SpeedMultiplier = 4
CurrencyMultiplier = 1.0
ColouredAttributes = true
DisableUnprotectedContracts = true
HideNonPublicBids = true
IncreaseToSevenSubs = true
RegenFixes = true
ForceLoadAllPlayers = false
AddTapaniRegenCode = false
UnCap20s = false
RemoveForeignPlayerLimit = false
NoWorkPermits = false
ChangeTo1280x800 = false
AutoLoadPatchFiles = false
PatchFileDirectory = .
DataDirectory = data
Debug = false

It also applies some patches by default that you cannot manipulate (these are Disable Remove CD Message, Remove Splash Screen, Allow CM0102 Window Close, Idle Sensitivity, Show position in the Tactics view and things to make CM0102 more portable (remove memory check, location check, etc))

You can set which .ini file CM0102Loader loads by passing a parameter (e.g." CM0102Loader.exe different_settings.ini"). But by default it will use "CM0102Loader.ini".

The AutoLoadPatchFiles option, when set to true, will look for .patch files in your CM0102 directory (or whatever directory PatchFileDirectory is set to. "." means the CM0102 directory) and apply those too. A good source of .patch files can be found at: https://github.com/nckstwrt/CM0102Patcher/blob/master/MiscPatches.zip (click Download)

DataDirectory allows you to set another directory for CM0102 to load its data from. This is normally the Data directory. But you can now copy this directory in the same folder (e.g. Oct2019) then maybe copy over the October 2019 update from www.champman0102.co.uk into the new directory, then set DataDirectory = Oct2019 and then it will load using the 2019 data.

Try Debug = true if you find your Saturn/Tapani exe is exiting without an error sometimes. It might just, weirdly, fix it!

You can also add an option like "DumpEXE = Patched.exe" and that will write out a patched exe file that you can use without the loader after running (so you can use the loader like a patcher if need be)

With version 1.8 you can also start CM0102Loader with the commandline option "-patch patch1.patch -patch patch2.patch" to load in patch files too.

This Loader was built with Visual C++ 6 so that it can run on Win95 as easy as it does on Win10. Which also should work on things like PlayOnMac, etc.