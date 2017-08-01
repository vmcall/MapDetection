# MapDetection
Detect manualmapped images remotely, without hassle

Extreme Injector -> detected
Xenos -> detected (even with Add Loader reference enabled)

How does it work?
First, it iterates every running thread owned by specified process, it then gets thread start address and then gets the allocation base of said thread.
The allocation base is the start of the allocation/memory section, for modules in memory the is the start of the pe header (it always is)
It then scans every unique allocation base for any anomalies it might have.
First, it checks the PE headers of said module to check if they are valid (it checks the MZ signature, the PE magic bytes and architectures)
If they are, it checks if the module is linked in the module list.

Example of a manually mapped, possibly malicious, image that was picked up by MapDetection
![Map Detection](https://i.imgur.com/uGJUbrQ.png)
