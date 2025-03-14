[![Codacy Badge](https://api.codacy.com/project/badge/Grade/983675f415f5405da0846ec33156092f)](https://www.codacy.com/app/raspopov/po-localization?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=raspopov/po-localization&amp;utm_campaign=Badge_Grade)

PO-Localization
===============

This is a library designed to help C++ developers in creating Windows
application to translate it on world languages. Project contains an
utility to convert existing resources of application in PO-file and
adds ability to use translated PO-files to application itself.
The PO-file is a native format of poEdit (a very convenient application
for translators).

Compression
-----------

Library can load translations in uncompressed or compressed formats
(Lempel-Ziv algorithm only). Uncompressed files has ".po" extension and
compressed ones has ".p_" extension. Compressed files can be produced
by Microsoft File Compression Utility named "compress.exe". It can be
found in any old Microsoft OS or Resource Kit. Usage example:

	compress.exe you_application.exe.09.po you_application.exe.09.p_

Compressed files can be also inserted as resources (detected by magic
number 'SZDD' at beginning of file).

Library uses WinAPI LZExpand library (Lz32.dll) to handle compressed
files.

Note: Some versions of compress.exe produces incorrect compressed files
(1 byte differ) just get another version of utility.

EXE to PO file converter usage
------------------------------

	exe2po.exe {input file.exe} {output file.po}

NOTE: You can ease converter usage by dropping exe2po.exe to Windows folder
and registering "Create PO" context menu by merging with "exe2po-register.reg"
file (undo with "exe2po-unregister.reg" file).

Generated .po-file blocks for menu resources:

	#: MENUPOPUP.{menu-id}.{ordinal}
	msgid "English menu popup"
	msgstr ""

	#: MENUITEM.{menu-id}.{menu-item-id}
	msgid "English menu item"
	msgstr ""

	Where {ordinal} is a number 0, 1, 2 etc.

Generated .po-file blocks for dialog box resources:

	#: DIALOGCAPTION.{dialog-id}
	msgid "English dialog caption"
	msgstr ""

	#: DIALOGCONTROL.{dialog-id}.{control-class}.{dialog-control-id}
	msgid "English dialog control"
	msgstr ""

Where {control-class} is a "Button", "Static" etc.
If dialog control id is a 0xffff then {dialog-control-id} = ( 0x80000000 | ordinal ) where ordinal is a number 0, 1, 2 etc.

Generated .po-file blocks for string resources:

	#: STRING.{string-id}
	msgid "English string"
	msgstr ""

License
-------

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Copyrights
----------

* PO-Localization

Copyright (C) Nikolay Raspopov, 2011-2023.

https://www.cherubicsoft.com/en/projects/po-localization/

* Microsoft (R) File Compression Utility Version 2.50

Copyright (C) Microsoft Corp. 1990-1994. All rights reserved.
