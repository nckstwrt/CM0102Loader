# CM0102Loader v1.1
Loader for Championship Manager 01/02

## Downloads
https://github.com/nckstwrt/CM0102Loader/releases

## Description
CM0102Loader is an .exe file you put in the same directory as your CM0102.exe (only works with a clean 3.9.68 version).
CM0102Loader can patch the .exe in memory and changes no other files - so there will be no permanent changes.

## Options
When you run CM0102Loader.exe for the first time it will create a CM0102Loader.ini file with the following default options:
```
Year = 2001
SpeedMultiplier = 4
CurrencyMultiplier = 1.0
ColouredAttributes = true
DisableUnprotectedContracts = true
HideNonPublicBids = true
IncreaseToSevenSubs = true
RemoveForeignPlayerLimit = false
NoWorkPermits = false
ChangeTo1280x800 = false
AutoLoadPatchFiles = false
DataDirectory = data
```
It also applies some patches by default that you cannot manipulate (these are Disable Remove CD Message, Remove Splash Screen, Allow CM0102 Window Close, Idle Sensitivity and things to make CM0102 more portable (remove memory check, location check, etc))

The AutoLoadPatchFiles option, when set to true, will look for .patch files in your CM0102 directory and apply those too. A good source of .patch files can be found at:
https://github.com/nckstwrt/CM0102Patcher/blob/master/MiscPatches.zip (click Download)

DataDirectory allows you to set another directory for CM0102 to load its data from. This is normally the Data directory. But you can now copy this directory in the same folder, [b]ensuring the new name has no spaces[/b] (e.g. Oct2019), then maybe copy over the October 2019 update from www.champman0102.co.uk into the new directory, then set DataDirectory = Oct2019 ([b]no[/b] quotes (") needed) and then it will load using the 2019 data.

This Loader was built with Visual C++ 6 so that it can run on Win95 as easy as it does on Win10. Which also should work on things like PlayOnMac, etc.
