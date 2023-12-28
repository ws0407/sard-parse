只包含单个文件：

##### CWE122: 3486 - Heap-based Buffer Overflow

A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine such as malloc().

##### CWE121: 3048 - Stack-based Buffer Overflow

+ Description
  A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).
+ Alternate Terms
  "Stack Overflow" is often used to mean the same thing as stack-based buffer overflow, however it is also used on occasion to mean stack exhaustion, usually a result from an excessively recursive function call. Due to the ambiguity of the term, use of stack overflow to describe either circumstance is discouraged.

##### CWE78: 2800 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

+ Description
  The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.
+ Extended Description
  This could allow attackers to execute unexpected, dangerous commands directly on the operating system. This weakness can lead to a vulnerability in environments in which the attacker does not have direct access to the operating system, such as in web applications. Alternately, if the weakness occurs in a privileged program, it could allow the attacker to specify commands that normally would not be accessible, or to call alternate commands with privileges that the attacker does not have. The problem is exacerbated if the compromised process does not follow the principle of least privilege, because the attacker-controlled commands may run with special system privileges that increases the amount of damage.

There are at least two subtypes of OS command injection:

The application intends to execute a single, fixed program that is under its own control. It intends to use externally-supplied inputs as arguments to that program. For example, the program might use system("nslookup [HOSTNAME]") to run nslookup and allow the user to supply a HOSTNAME, which is used as an argument. Attackers cannot prevent nslookup from executing. However, if the program does not remove command separators from the HOSTNAME argument, attackers could place the separators into the arguments, which allows them to execute their own program after nslookup has finished executing.
The application accepts an input that it uses to fully select which program to run, as well as which commands to use. The application simply redirects this entire command to the operating system. For example, the program might use "exec([COMMAND])" to execute the [COMMAND] that was supplied by the user. If the COMMAND is under attacker control, then the attacker can execute arbitrary commands or programs. If the command is being executed using functions like exec() and CreateProcess(), the attacker might not be able to combine multiple commands together in the same line.
From a weakness standpoint, these variants represent distinct programmer errors. In the first variant, the programmer clearly intends that input from untrusted parties will be part of the arguments in the command to be executed. In the second variant, the programmer does not intend for the command to be accessible to any untrusted party, but the programmer probably has not accounted for alternate ways in which malicious attackers can provide input.

##### CWE190: 2448 - Integer Overflow or Wraparound

+ Description
  The product performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value. This can introduce other weaknesses when the calculation is used for resource management or execution control.
+ Extended Description
  An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation. When this occurs, the value may wrap to become a very small or negative number. While this may be intended behavior in circumstances that rely on wrapping, it can have security consequences if the wrap is unexpected. This is especially the case if the integer overflow can be triggered using user-supplied inputs. This becomes security-critical when the result is used to control looping, make a security decision, or determine the offset or size in behaviors such as memory allocation, copying, concatenation, etc.

##### CWE762: 2072 - Mismatched Memory Management Routines

+ Description
  The product attempts to return a memory resource to the system, but it calls a release function that is not compatible with the function that was originally used to allocate that resource.
+ Extended Description
  This weakness can be generally described as mismatching memory management routines, such as:

- The memory was allocated on the stack (automatically), but it was deallocated using the memory management routine free() (CWE-590), which is intended for explicitly allocated heap memory.
- The memory was allocated explicitly using one set of memory management functions, and deallocated using a different set. For example, memory might be allocated with malloc() in C++ instead of the new operator, and then deallocated with the delete operator.
  When the memory management functions are mismatched, the consequences may be as severe as code execution, memory corruption, or program crash. Consequences and ease of exploit will vary depending on the implementation of the routines and the object being managed.

##### CWE191: 1860 - Integer Underflow (Wrap or Wraparound)

+ Description
  The product subtracts one value from another, such that the result is less than the minimum allowable integer value, which produces a value that is not equal to the correct result.
+ Extended Description
  This can happen in signed and unsigned cases.
+ Alternate Terms

- "Integer underflow" is sometimes used to identify signedness errors in which an originally positive number becomes negative as a result of subtraction. However, there are cases of bad subtraction in which unsigned integers are involved, so it's not always a signedness issue.
- "Integer underflow" is occasionally used to describe array index errors in which the index is negative.

##### CWE134: 1680 - Use of Externally-Controlled Format String

+ Description
  The product uses a function that accepts a format string as an argument, but the format string originates from an external source.
+ Extended Description
  When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.
  It should be noted that in some circumstances, such as internationalization, the set of format strings is externally controlled by design. If the source of these format strings is trusted (e.g. only contained in library files that are only modifiable by the system administrator), then the external control might not itself pose a vulnerability.

##### CWE590: 1675 - Free of Memory not on the Heap

+ Description
  The product calls free() on a pointer to memory that was not allocated using associated heap allocation functions such as malloc(), calloc(), or realloc().
+ Extended Description
  When free() is called on an invalid pointer, the program's memory management data structures may become corrupted. This corruption can cause the program to crash or, in some circumstances, an attacker may be able to cause free() to operate on controllable memory locations to modify critical program variables or execute code.

##### CWE23: 1400 - Relative Path Traversal

+ Description
  The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory.
+ Extended Description
  This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.

##### CWE36: 1400 - Absolute Path Traversal

+ Description
  The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as "/abs/path" that can resolve to a location that is outside of that directory.
+ Extended Description
  This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.

##### CWE124: 1228 - Buffer Underwrite ('Buffer Underflow')

+ Description
  The product writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.
+ Extended Description
  This typically occurs when a pointer or its index is decremented to a position before the buffer, when pointer arithmetic results in a position before the beginning of the valid memory location, or when a negative index is used.
+ Alternate Terms
  "Buffer underflow" is more commonly used, although both terms are also sometimes used to describe a buffer under-read (CWE-127).

##### CWE127: 1228 - Buffer Under-read

+ Description
  The product reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations prior to the targeted buffer.
+ Extended Description
  This typically occurs when the pointer or its index is decremented to a position before the buffer, when pointer arithmetic results in a position before the beginning of the valid memory location, or when a negative index is used. This may result in exposure of sensitive information or possibly a crash.

##### CWE401: 1032 - Missing Release of Memory after Effective Lifetime

+ Description
  The product does not sufficiently track and release allocated memory after it has been used, which slowly consumes remaining memory.
+ Extended Description
  This is often triggered by improper handling of malformed data or unexpectedly interrupted sessions. In some languages, developers are responsible for tracking memory allocation and releasing the memory. If there are no more pointers or references to the memory, then it can no longer be tracked and identified for release.
+ Alternate Terms
  Memory Leak

##### CWE126: 912 - Buffer Over-read

+ Description
  The product reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations after the targeted buffer.
+ Extended Description
  This typically occurs when the pointer or its index is incremented to a position beyond the bounds of the buffer or when pointer arithmetic results in a position outside of the valid memory location to name a few. This may result in exposure of sensitive information or possibly a crash.

##### CWE457: 817 - Use of Uninitialized Variable

+ Description
  The code uses a variable that has not been initialized, leading to unpredictable or unintended results.
+ Extended Description
  In some languages such as C and C++, stack variables are not initialized by default. They generally contain junk data with the contents of stack memory before the function was invoked. An attacker can sometimes control or read these contents. In other languages or conditions, a variable that is not explicitly initialized can be given a default value that has security implications, depending on the logic of the program. The presence of an uninitialized variable can sometimes indicate a typographic error in the code.

##### CWE253: 684 - Incorrect Check of Function Return Value

+ Description
  The product incorrectly checks a return value from a function, which prevents it from detecting errors or exceptional conditions.
+ Extended Description
  Important and common functions will return some value about the success of its actions. This will alert the program whether or not to handle any errors caused by that function.

##### CWE194: 672 - Unexpected Sign Extension

+ Description
  The product performs an operation on a number that causes it to be sign extended when it is transformed into a larger data type. When the original number is negative, this can produce unexpected values that lead to resultant weaknesses.

##### CWE195: 672 - Signed to Unsigned Conversion Error

+ Description
  The product uses a signed primitive and performs a cast to an unsigned primitive, which can produce an unexpected value if the value of the signed primitive can not be represented using an unsigned primitive.
+ Extended Description
  It is dangerous to rely on implicit casts between signed and unsigned numbers because the result can take on an unexpected value and violate assumptions made by the program.

Often, functions will return negative values to indicate a failure. When the result of a function is to be used as a size parameter, using these negative return values can have unexpected results. For example, if negative size values are passed to the standard memory copy or allocation functions they will be implicitly cast to a large unsigned value. This may lead to an exploitable buffer overflow or underflow condition.

##### CWE252: 630 - Unchecked Return Value

+ Description
  The product does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions.
+ Extended Description
  Two common programmer assumptions are "this function call can never fail" and "it doesn't matter if this function call fails". If an attacker can force the function to fail or otherwise return a value that is not expected, then the subsequent program logic could lead to a vulnerability, because the product is not in a state that the programmer assumes. For example, if the program calls a function to drop privileges but does not check the return code to ensure that privileges were successfully dropped, then the program will continue to operate with the higher privileges.

##### CWE758: 581 - Reliance on Undefined, Unspecified, or Implementation-Defined Behavior

+ Description
  The product uses an API function, data structure, or other entity in a way that relies on properties that are not always guaranteed to hold for that entity.
+ Extended Description
  This can lead to resultant weaknesses when the required properties change, such as when the product is ported to a different platform or if an interaction error (CWE-435) occurs.

##### CWE415: 560 - Double Free

+ Description
  The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations.
+ Extended Description
  When a program calls free() twice with the same argument, the program's memory management data structures become corrupted. This corruption can cause the program to crash or, in some circumstances, cause two later calls to malloc() to return the same pointer. If malloc() returns the same value twice and the program later gives the attacker control over the data that is written into this doubly-allocated memory, the program becomes vulnerable to a buffer overflow attack.

##### CWE690: 560 - Unchecked Return Value to NULL Pointer Dereference

+ Description
  The product does not check for an error after calling a function that can return with a NULL pointer if the function fails, which leads to a resultant NULL pointer dereference.

##### CWE789: 560 - Memory Allocation with Excessive Size Value

+ Description
  The product allocates memory based on an untrusted, large size value, but it does not ensure that the size is within expected limits, allowing arbitrary amounts of memory to be allocated.
+ Alternate Terms
  Stack Exhaustion:
  When a weakness allocates excessive memory on the stack, it is often described as "stack exhaustion," which is a technical impact of the weakness. This technical impact is often encountered as a consequence of CWE-789 and/or CWE-1325.

##### CWE197: 504 - Numeric Truncation Error

+ Description
  Truncation errors occur when a primitive is cast to a primitive of a smaller size and data is lost in the conversion.
+ Extended Description
  When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original value. This value may be required as an index into a buffer, a loop iterator, or simply necessary state data. In any case, the value cannot be trusted and the system will be in an undefined state. While this method may be employed viably to isolate the low bits of a value, this usage is rare, and truncation usually implies that an implementation error has occurred.

##### CWE369: 504 - Divide By Zero

+ Description
  The product divides a value by zero.
+ Extended Description
  This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected. It frequently occurs in calculations involving physical dimensions such as size, length, width, and height.

##### CWE400: 420 - Uncontrolled Resource Consumption

+ Description
  The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources.
+ Extended Description
  Limited resources include memory, file system storage, database connection pool entries, and CPU. If an attacker can trigger the allocation of these limited resources, but the number or size of the resources is not controlled, then the attacker could cause a denial of service that consumes all available resources. This would prevent valid users from accessing the product, and it could potentially have an impact on the surrounding environment. For example, a memory exhaustion attack against an application could slow down the application as well as its host operating system.
  There are at least three distinct scenarios which can commonly lead to resource exhaustion:

- Lack of throttling for the number of allocated resources
- Losing all references to a resource before reaching the shutdown stage
- Not closing/returning a resource after processing
  Resource exhaustion problems are often result due to an incorrect implementation of the following situations:
- Error conditions and other exceptional circumstances.
- Confusion over which part of the program is responsible for releasing the resource.

##### CWE416: 398 - Use After Free

+ Description
  Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.
+ Extended Description
  The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timing of the flaw. The simplest way data corruption may occur involves the system's reuse of the freed memory. Use-after-free errors have two common and sometimes overlapping causes:

- Error conditions and other exceptional circumstances.
- Confusion over which part of the program is responsible for freeing the memory.
  In this scenario, the memory in question is allocated to another pointer validly at some point after it has been freed. The original pointer to the freed memory is used again and points to somewhere within the new allocation. As the data is changed, it corrupts the validly used memory; this induces undefined behavior in the process.
  If the newly allocated data happens to hold a class, in C++ for example, various function pointers may be scattered within the heap data. If one of these function pointers is overwritten with an address to valid shellcode, execution of arbitrary code can be achieved.

##### CWE563: 366 - Assignment to Variable without Use

+ Description
  The variable's value is assigned but never used, making it a dead store.
+ Extended Description
  After the assignment, the variable is either assigned another value or goes out of scope. It is likely that the variable is simply vestigial, but it is also possible that the unused variable points out a bug.

##### CWE114: 336 - Process Control

+ Description
  Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker.
+ Extended Description
  Process control vulnerabilities take two forms:

- An attacker can change the command that the program executes: the attacker explicitly controls what the command is.
- An attacker can change the environment in which the command executes: the attacker implicitly controls what the command means.
  Process control vulnerabilities of the first type occur when either data enters the application from an untrusted source and the data is used as part of a string representing a command that is executed by the application. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.

##### CWE680: 336 - Integer Overflow to Buffer Overflow

+ Description
  The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.

##### CWE761: 336 - Free of Pointer not at Start of Buffer

+ Description
  The product calls free() on a pointer to a memory resource that was allocated on the heap, but the pointer is not at the start of the buffer.
+ Extended Description
  This can cause the product to crash, or in some cases, modify critical program variables or execute code.
  This weakness often occurs when the memory is allocated explicitly on the heap with one of the malloc() family functions and free() is called, but pointer arithmetic has caused the pointer to be in the interior or end of the buffer.

##### CWE427: 280 - Uncontrolled Search Path Element

+ Description
  The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.
+ Extended Description
  Although this weakness can occur with any type of resource, it is frequently introduced when a product uses a directory search path to find executables or code libraries, but the path contains a directory that can be modified by an attacker, such as "/tmp" or the current working directory.
  In Windows-based systems, when the LoadLibrary or LoadLibraryEx function is called with a DLL name that does not contain a fully qualified path, the function follows a search order that includes two path elements that might be uncontrolled:

- the directory from which the program has been loaded
- the current working directory
  In some cases, the attack can be conducted remotely, such as when SMB or WebDAV network shares are used.
  One or more locations in that path could include the Windows drive root or its subdirectories. This often exists in Linux-based code assuming the controlled nature of the root directory (/) or its subdirectories (/etc, etc), or a code that recursively accesses the parent directory. In Windows, the drive root and some of its subdirectories have weak permissions by default, which makes them uncontrolled.
  In some Unix-based systems, a PATH might be created that contains an empty element, e.g. by splicing an empty variable into the PATH. This empty element can be interpreted as equivalent to the current working directory, which might be an untrusted search element.
  In software package management frameworks (e.g., npm, RubyGems, or PyPi), the framework may identify dependencies on third-party libraries or other packages, then consult a repository that contains the desired package. The framework may search a public repository before a private repository. This could be exploited by attackers by placing a malicious package in the public repository that has the same name as a package from the private repository. The search path might not be directly under control of the developer relying on the framework, but this search order effectively contains an untrusted element.

##### CWE606: 280 - Unchecked Input for Loop Condition

+ Description
  The product does not properly check inputs that are used for loop conditions, potentially leading to a denial of service or other consequences because of excessive looping.

##### CWE90: 280 - Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

+ Description
  The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.

##### CWE272: 252 - Least Privilege Violation

+ Description
  The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.

##### CWE476: 236 - NULL Pointer Dereference

+ Description
  A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.
+ Extended Description
  NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.
+ Alternate Terms

- NPD
- null deref
- nil pointer dereference:	used for access of nil in Go programs

##### CWE404: 224 - Improper Resource Shutdown or Release

+ Description
  The product does not release or incorrectly releases a resource before it is made available for re-use.
+ Extended Description
  When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set period of time or revocation.

CWE284: 216

CWE617: 186

CWE398: 181

CWE506: 158

CWE377: 144

CWE319: 112

CWE426: 112

CWE665: 112

CWE675: 112

CWE390: 90

CWE546: 90

CWE666: 90

CWE123: 84

CWE773: 84

CWE775: 84

CWE226: 72

CWE244: 72

CWE325: 72

CWE511: 72

CWE510: 70

CWE256: 56

CWE259: 56

CWE321: 56

CWE591: 56

CWE327: 54

CWE328: 54

CWE391: 54

CWE396: 54

CWE467: 54

CWE681: 54

CWE588: 50

CWE843: 50

CWE468: 37

CWE188: 36

CWE273: 36

CWE366: 36

CWE367: 36

CWE459: 36

CWE469: 36

CWE475: 36

CWE534: 36

CWE535: 36

CWE15: 28

CWE176: 28

CWE464: 28

CWE672: 27

CWE397: 20

CWE483: 20

CWE196: 18

CWE222: 18

CWE223: 18

CWE242: 18

CWE247: 18

CWE338: 18

CWE364: 18

CWE478: 18

CWE479: 18

CWE480: 18

CWE481: 18

CWE482: 18

CWE484: 18

CWE526: 18

CWE587: 18

CWE605: 18

CWE615: 18

CWE620: 18

CWE667: 18

CWE676: 18

CWE685: 18

CWE688: 18

CWE780: 18

CWE785: 18

CWE832: 18

CWE570: 16

CWE571: 16

CWE835: 6

CWE562: 3

CWE561: 2

CWE674: 2

CWE440: 1
