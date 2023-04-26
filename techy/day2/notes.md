## Day 2 - Zip File headers - python wheels

For Day 2, I'm looking at python `whl` files, which according to [PEP 427](https://peps.python.org/pep-0427/) are just zip files :) 

I've been doing a lot of work in writing detections around malicious PyPi packages using [guarddog](https://github.com/DataDog/guarddog), so a hunt rule to find `whl` files sounds like fun. But how do I differentiate a `whl` file from a `php` based phishing kit?

Let's look at the first 10 bytes of each

```bash
└> ls
chase.zip  requests-2.28.2-py3-none-any.whl  zipfile.yar
(venv) ┌[zack.allen☮COMP-L470T06VG0]-(~/git/2023/techy/day2)-[git://techy ✗]-
└> od -t x1 -N 10 requests-2.28.2-py3-none-any.whl
0000000 50 4b 03 04 14 00 00 00 08 00
0000012
(venv) ┌[zack.allen☮COMP-L470T06VG0]-(~/git/2023/techy/day2)-[git://techy ✗]-
└> od -t x1 -N 10 chase.zip
0000000 50 4b 03 04 14 00 00 00 08 00
0000012
```

`504b0304` / `04034b50` in hex is a zip file!

I guess this means I can use `unzip` to list the files inside?

```bash
└> unzip -l requests-2.28.2-py3-none-any.whl
Archive:  requests-2.28.2-py3-none-any.whl
  Length      Date    Time    Name
---------  ---------- -----   ----
     4972  01-12-2023 16:16   requests/__init__.py
      435  01-12-2023 16:16   requests/__version__.py
     1397  01-12-2023 16:16   requests/_internal_utils.py
    21287  01-12-2023 16:16   requests/adapters.py
     6377  01-12-2023 16:16   requests/api.py
    10187  01-12-2023 16:16   requests/auth.py
      429  01-12-2023 16:16   requests/certs.py
     1451  01-12-2023 16:16   requests/compat.py
    18560  01-12-2023 16:16   requests/cookies.py
     3811  01-12-2023 16:16   requests/exceptions.py
     3875  01-12-2023 16:16   requests/help.py
      733  01-12-2023 16:16   requests/hooks.py
    35223  01-12-2023 16:16   requests/models.py
      957  01-12-2023 16:16   requests/packages.py
    30180  01-12-2023 16:16   requests/sessions.py
     4235  01-12-2023 16:16   requests/status_codes.py
     2912  01-12-2023 16:16   requests/structures.py
    33228  01-12-2023 16:16   requests/utils.py
    10142  01-12-2023 16:24   requests-2.28.2.dist-info/LICENSE
     4619  01-12-2023 16:24   requests-2.28.2.dist-info/METADATA
       92  01-12-2023 16:24   requests-2.28.2.dist-info/WHEEL
        9  01-12-2023 16:24   requests-2.28.2.dist-info/top_level.txt
     1775  01-12-2023 16:24   requests-2.28.2.dist-info/RECORD
---------                     -------
   196886                     23 files
```

A PEP-427 compliant `whl` file needs a `*-distinfo/` directory and at least `METADATA` and `RECORD` file.

What if we use the methodology from the Day 1 Zip filename matcher for `dist-info/METADATA` and `dist-info/WHEEL`?
