# MapDetection
Detect manualmapped images remotely, without hassle

## Confirmed Detections
+ Extreme Injector -> detected
+ Xenos -> detected (even with Add Loader reference enabled)

## How does it work?
MapDetection has two modes, deep and quick.

### Quick mode 
Iterates every process thread, saves all unique allocation bases. It then scans every unique allocation base for any anomalies.

### Deep mode
Deep mode will run quick scan, then continue to traverse the virtual memory space for any executable pages that do not belong to a module.

## Anomalies MapDetection looks for
+ Valid PE headers (MZ signature, PE magic bytes and architecture)
+ Module is linked correctly to module list
+ Valid allocation type (MEM_IMAGE)
+ Valid allocation flags

## Example of a manually mapped, possibly malicious, image that was picked up by MapDetection
![Map Detection](https://i.imgur.com/uGJUbrQ.png)
