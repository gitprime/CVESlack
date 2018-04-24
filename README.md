## CVESlack
Spinoff of [CVEStack](https://github.com/Plazmaz/CVEStack) to be slack-centric. Scans feeds for various elements within the stack, then posts to a slack webhook. Supports a pip-style format. For instance, this file:
```
linux
wordpress
````
Will post to slack for any new (or recently updated) CVEs matching `linux` or `wordpress`.
You can use `__` to determine left or right padding on a per-pattern basis. For instance, `__py` would match ` testpy`, but not `testpy `. Similarly, `py__` would match `testpy `, but not ` testpy`.
You could also require a version number. **Please note this might return false negatives. NVD does not provide formal version data.**. 
You can use this feature by doing something like:
```
linux==4.13
```

The example config pulls from nvd and seclists. It posts to a nonexistent webhook by default.
