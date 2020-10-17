PS2 ELF Types Extractor to C++
-------------------------------

License: **MIT**

Tested on IDA Pro 7.2 with Python 2.7.18

Usage
-----
 * In IDA: File > Script File
 * Then in disassembly put the cursor on the start of class vftable
 * Go to Edit > Other > Generate C/C++ Class Defs
 * Look into "Output window", your class will be there

Will be later
-------------
 * Custom dialog window with generated class
 * Function construction deduction with size prediction (only for ReHitman project) and members generation
 * Return type prediction: based on patterns but it could be useful for somebody

Etc
---

This project is a part of [ReHitman](https://github.com/ReGlacier/ReHitman) project