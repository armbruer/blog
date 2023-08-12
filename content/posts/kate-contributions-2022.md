---
title: "Kontributions to Kate and KTextEditor in 2022"
date: 2023-08-11T16:49:11+02:00
draft: false
images: []
resources:
- name: "featured-image"
  src: "kate-welcome-page.png"
lightgallery: true
---

During my third semester at TUM, I switched my OS from Windows to Linux. This happened mostly out of curiosity and wanting to learn about Linux, but also because all the "cool geeks" seemed to use some version of Linux. I ended up with  the Kubuntu distribution, which ships with the Plasma Desktop and KDE applications simply because it looked a bit like Windows. Ever since that (ca. end of 2018), I have been an enthusiastic user of Plasma.

Constantly following the updates from [Nate's blog](https://pointieststick.com/) about ongoing Plasma and KDE Development I got interested more and more. Last year I finally decided to contribute myself to the [KDE community](https://kde.org).

I had no prior experience working with (large) C++ codebases and no experience with Qt at all. After looking a while for easy merge requests, I ended up making several contributions to the [Kate](https://kate-editor.org/) text editor and to KTextEditor, a framework for building Qt-based text editors.

## First Contribution

My first ever contribution was a [MR that opens Kate's Projects View](https://invent.kde.org/utilities/kate/-/merge_requests/669) whenever a folder is opened. This is to provide some sort of visual feedback to the user when the "Open Folder..." action is clicked.

## Features

Most interesting are probably the features I worked on:

- [a Welcome Screen for Kate and KWrite]( https://invent.kde.org/utilities/kate/-/merge_requests/888), in collaboration with several other people
- [making the LSP context menu items only show up contextually, i.e. when a LSP server is available](https://invent.kde.org/utilities/kate/-/merge_requests/974)
- [an action to hide all toolviews](https://invent.kde.org/utilities/kate/-/merge_requests/749)
- [actions for more convenient view splitting in Kate](https://invent.kde.org/utilities/kate/-/merge_requests/695) 
- [an action to detach tabs into a new window](https://invent.kde.org/utilities/kate/-/merge_requests/892)


My personal favorite is the [clipboard history dialog](https://invent.kde.org/frameworks/ktexteditor/-/merge_requests/390) I implemented for all KTextEditor based applications. It supports searching through clipboard entries and showing a syntax highlighted preview of the clipboard entries. See yourself below:

{{< rawhtml >}}
<video width=100% controls>
<source src="/videos/clipboard-history-dialog.mp4" type="video/mp4">
Your browser does not support the video tag :P</video>
{{< /rawhtml >}}

## Usability Improvements

Another set of changes was focused around improving usability in Kate. This meant adding icons, using icons consistently ([link 1](https://invent.kde.org/utilities/kate/-/merge_requests/843), [link 2](https://invent.kde.org/utilities/kate/-/merge_requests/802), [link 3](https://invent.kde.org/utilities/kate/-/merge_requests/798)), rearranging actions in the menu bar to be organized more logically ([link 1](https://invent.kde.org/utilities/kate/-/merge_requests/673), [link 2](https://invent.kde.org/utilities/kate/-/merge_requests/705), [link 3](https://invent.kde.org/utilities/kate/-/merge_requests/678), [link 4](https://invent.kde.org/utilities/kate/-/merge_requests/702), [link 5](https://invent.kde.org/frameworks/ktexteditor/-/merge_requests/353), [link 6](https://invent.kde.org/frameworks/ktexteditor/-/merge_requests/337)), assigning good default shortcuts ([link 1](https://invent.kde.org/utilities/kate/-/merge_requests/902), [link 2](https://invent.kde.org/utilities/kate/-/merge_requests/900)), and ensuring consistent behavior for actions ([link 1](https://invent.kde.org/utilities/kate/-/merge_requests/889)) and a more consistent layout for context menus ([link 1](https://invent.kde.org/utilities/kate/-/merge_requests/889)).


Adding default server configurations for several LSP servers:

- [Kotlin, Lua, HTML, YAML and Docker](https://invent.kde.org/utilities/kate/-/merge_requests/706)
- [C-Sharp](https://invent.kde.org/utilities/kate/-/merge_requests/713)

Small improvements to Kate's LSP client:

- [Adding support for expand and shrink selection actions](https://invent.kde.org/utilities/kate/-/merge_requests/719)
- [a rootfile pattern as an alternative for detecting the rootpath of the LSP server](https://invent.kde.org/utilities/kate/-/merge_requests/907)
- [shortening paths shown in the treeview](https://invent.kde.org/utilities/kate/-/merge_requests/893)

## Bugfixes

I also ended up fixing several bugs and crashes:

- [Add files opened via open action to recent files](https://invent.kde.org/utilities/kate/-/merge_requests/993)
- [filetree: fix closing when close button is disabled ](https://invent.kde.org/utilities/kate/-/merge_requests/896)
- [Fix crash when there are no search results ](https://invent.kde.org/utilities/kate/-/merge_requests/853)


Finally, I would like to say thank you to Christoph Cullmann and Waqar Ahmed, 
who reviewed my code and helped me bring it into a mergable state.
