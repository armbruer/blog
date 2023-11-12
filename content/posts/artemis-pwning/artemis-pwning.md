---
title: "Artemis Pwning"
date: 2023-08-14T08:55:14+02:00
author: Eric Armbruster
draft: false

tags: 
- Vulnerability
- Red-Teaming
- Offensive-Security
categories:
- CyberSec
---

# Pwning Artemis for fun and profit

During the course, "WebApplication Security", we received the task to find security vulnerabilities within [Artemis](https://github.com/ls1intum/Artemis), TUM's own learning platform, widely deployed in large-scale (programming) courses at the computer science faculty.

Within this blogpost I want to shortly discuss the security vulnerabilities I found in a writeup style. 
If you are interested in more detail read the [full report](/pdfs/report.pdf) and the [slides](/pdfs/slides.pdf) of the talk my colleague and friend Florian Freund and I held.

## Limited File Overwrite


### Type

file delete, file overwrite, file creation

### Description 

The request body of the endpoints `createAttachment` and `updateAttachment`
in `AttachmentResource.java` allows setting a file path via the JSON attribute link of
the `Attachment` object. The actual file upload and file save that needs to be done
when creating or updating an attachment is handled via the `saveFile` endpoint in
`FileResource.java`. Among under methods `manageFilesForUpdatedFilePath` is called
to actually store the file on disk. Particularly interesting is that a file path parameter
called `newFilePath` is passed that is taken from the link JSON API value and can be
controlled by an attacker without any sanitization.

The code below is an extract of the most important part of `manageFilesForUpdatedFilePath`. 
The problem is that `generateTargetFile` is called with a file path and not as
the parameter name of said method implies with a file name. Moreover, the `generateTargetFile` 
method performs no sanitization if `keepFileName` is set to true, which is
fulfilled at least for the attachment endpoints listed above. Consequently, this can
be used to make `generateTargetFile` create the `targetFile` with empty contents at an
arbitrary location that overwrites the file previously saved at this location. Because of line
4 and 9 below, we can also fill the file with arbitrary contents:


### Impact

The impact of this vulnerability is estimated to be medium-to-low, as at minimum 
the role editor is required to exploit it. Furthermore, it is limited by the requirements
for file uploads set in the `handleSaveFile` method in `FileResource.java`. This method
ensures that file names have one of the following file endings: png, jpg, jpeg, svg, pdf,
zip. Also, the uploaded files must adhere to the file size limit set in application.yml,
which is by default 10 MB.

### Workarounds and Fixes

The main problem here is that the file upload mechanism first stores the file in a temporary path and then a second user request is expected to
make the server move the file into the final directory. In order for this to work, the
link attribute must contain a path to the temporary file. But this path can be set utterly
independent of the path of the actually uploaded file. We do not provide suggestion
for a fix, as this requires a change in the design of the upload mechanism and this most
likely would require some larger code changes.

In the following we discuss ways to fix the problem without major code changes.
The underlying problem is that the method `generateTargetFile(newFilePath, ...)`
is called in `manageFilesForUpdatedFilePath` with a file path and not as the parameter
of `generateTargetFile` implies with a file name. The best solution probably would be to
ensure it is only called with the file name.

It is debatable, whether this call should be done in `generateTargetFile` or in `manageFilesForUpdatedFilePath`. In case it is done in the latter one needs to keep in mind that this bug could reappear again as soon as a different method calls `generateTargetFile` with an attacker controlled path as first argument. However, if this is solved in `generateTargetFile` it would leave some code lines in `manageFilesForUpdatedFilePath` unprotected, which could lead to problems in the future as well. Another solution to consider is to call it in both methods.

A different approach that was already employed in some other places in Artemis
would be to call `removeIllegalCharacters` in the `manageFilesForUpdatedFilePath`
method or in all endpoints that accept a file path. The method sanitizes file paths by
removing all "." and "/" characters from the argument it is handed.

## Arbitrary File and Folder Deletion

### Type

file and folder deletion

### Affected Endpoints

The following endpoints are vulnerable to the file and folder
deletion attack:
- `updateAttachment` and `deleteAttachment` in `AttachmentResource.java`
- `updateCourse` and `deleteCourse` in `CourseResource.java`
- `updateQuizExercise` and `deleteQuizExercise` in `QuizExerciseResource.java`

### Description

The method `manageFilesForUpdatedFilePath` is also vulnerable to file
deletion. The `oldFilePath` parameter in said method is attacker controlled when one
of the affected endpoints listed above is called. The problem is that `manageFilesForUpdatedFilePath` calls `FileSystemUtils.deleteRecursively(oldFile)`, where `oldFile`
is the corresponding File object to the attacker controlled Path `oldFilePath`. As there
is no check whether the `oldFilePath` corresponds to a file (and not a directory), we can
also utilize this call to delete arbitrary folders recursively.
On a side note, initially it looked like the method `actualPathForPublicPath`, which
is called before the delete call, would sanitize this path, because it internally executes
`publicPath.substring(publicPath.lastIndexOf("/") + 1);`. However, later in that
function the unsanitized `publicPath` is concatenated again to the returned path if it also
contains the string `files/attachments/attachment-unit` (some other strings work as well).
In order to exploit this, create a lecture attachment. Edit the attachment and set the
link JSON attribute to something like `files/attachments/attachment-unit/../../../../../../../<path to delete>`. Then edit the attachment again and set a different link (exact value does not matter), this time the deletion will be executed, as the `previousLink` will be placed
in `oldFilePath`. Please note, the edits must not be done via the UI, as it sends requests to
multiple endpoints, instead ensure only the request to the `updateAttachment` endpoint
is sent. Instead of a second edit, one can also delete the attachment.


### Impact

This vulnerability is estimated to be of low-to-medium severity, as a recursive
folder deletion could be abused to destroy the system or delete uploaded files by disliked
students. However, editor rights are required, thus we think it is rather unlikely to be
exploited.

### Workarounds and Fixes

The main problem here is the same as discussed for the previous vulnerability. This issue can be fixed without major code changes as well.

Firstly, this should be prevented by calling `removeIllegalCharacters` on `oldFilePath`
in `manageFilesForUpdatedFilePath`. Furthermore, the intention behind the call `FileSystemUtils.deleteRecursively(oldFile)` is to delete a single file, thus `Files.delete(path)` or another method that only deletes a single file should be called.

### Demo

The following is a short demo video that shows how a folder test is deleted by applying the vulnerability:

{{< rawhtml >}}
<video width=100% controls>
<source src="/videos/artemis-pwning-live-demo.mp4" type="video/mp4">
Your browser does not support the video tag :P</video>
{{< /rawhtml >}}
