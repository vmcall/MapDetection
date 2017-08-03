# MapDetection
Detect manualmapped images remotely, without hassle

## Confirmed Detections
+ Extreme Injector -> detected
+ Xenos -> detected (even with Add Loader reference enabled)

## How does it work?
First, it iterates every running thread owned by specified process, it then gets thread start address and then gets the allocation base of said thread.
For modules in memory, the allocation base is the start of the dos header (it always is)
It then scans every unique allocation base for any anomalies it might have.

## Anomalies MapDetection looks for
+ Valid PE headers (MZ signature, PE magic bytes and architecture)
+ Module is linked correctly to module list
+ Valid allocation type (MEM_IMAGE)
+ Valid allocation flags

## Example of a manually mapped, possibly malicious, image that was picked up by MapDetection
![Map Detection](https://i.imgur.com/uGJUbrQ.png)
