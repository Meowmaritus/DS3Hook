* Automatically hooks to DS3 upon calling a memory read/write function.
* Can be hooked/unhooked safely, even if your app crashes. Will NOT crash Dark Souls 3.
* Some credit goes to Wulf2k, he helped with some 64bit shit.

### Simple code example: Turn on LoHit Debug Draw
```cs
DS3Hook.Hook.WBool(0x144766C6C, true);
```