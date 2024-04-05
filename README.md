# ietf-reviewtool

This is a simple Python 3 tool to download and review IETF documents, such as
Internet-Drafts or RFCs, and comes packaged as a single `ietf-reviewtool`
script.

## About

`ietf-reviewtool` offers several different review tools:

* `fetch` downloads items (I-Ds, charters, RFCs, etc.) for review

* `fetch-agenda` downloads all items on the [agenda of the next IESG
  telechat](https://datatracker.ietf.org/iesg/agenda/) for review

* `strip` strips headers, footers and pagination from items, similar to the
  earlier [`rfcstrip`](https://tools.ietf.org/tools/rfcstrip/about) tool

* `review` extracts inline reviews from the indicated items and formats them for
  sharing by email or submission to the [IETF
  datatracker](https://datatracker.ietf.org/), with some functionality that is
  similar to the earlier
  [`idcomments`](https://tools.ietf.org/tools/idcomments/about) tool

This is a work in progress. Additional functionality will be added over time, so
there is a chance this documentation only covers a subset of what the actual
tool offers. You can get command line help on the various tools by passing
`--help` to `ietf-reviewtool` and its sub-tools.

## Installation

You can install this via [PyPI](https://pypi.org/project/ietf-reviewtool/):

``` shell
pip install ietf-reviewtool
```

## Usage

An example workflow of the tool is as follows.

### Downloading items

You first download the item for review:
``` shell
ietf-reviewtool fetch rfc1925.txt
```

This downloads the text version of
[RFC1925](https://datatracker.ietf.org/doc/html/rfc1925) into a text file named
`rfc1925.txt` and (by default) performs a `strip` operation on the file.

You will then open the stripped `rfc1925.txt` for review in your preferred text
editor.

### Reviewing

You can flag issues of three different severity levels, namely, "discuss",
"comment" and "nit". (These levels are inspired by the [IESG review
process](https://www.ietf.org/about/groups/iesg/statements/iesg-discuss-criteria/).)

In order to flag an issue of a given severity level, enter a new line at an
appropriate location in the document that reads `DISCUSS:`, `COMMENT:` or
`NIT:`.

#### Inline issues

Using `rfc1925.txt` as an example and using `***` to indicate the added review
content, you can flag an "inline" issue like this:
```
2. The Fundamental Truths

   (1)  It Has To Work.

***COMMENT: Well, duh.***
```

After saving the changed `rfc1925.txt`, you can then extract a formatted review
as:

```
Section 2, paragraph 2, comment:
Well, duh.
```

See below for how to extract a review.

Using `DISCUSS:` or `NIT:` instead of `COMMENT:` will change the severity of the
issue, as appropriate.

#### Issues with context

It is possible quote part of the original document, to give the review some context, like this:

```
***COMMENT:***
   (3)  With sufficient thrust, pigs fly just fine. However, this is
***Can we stop picking on pigs or pigeons?***
```

This will produce the following review:

```
Section 2, paragraph 5, comment:
>    (3)  With sufficient thrust, pigs fly just fine. However, this is

Can we stop picking on pigs or pigeons?
```

#### Inline nits

To quickly flag some editing nits, such as spelling errors, you can simply edit
the text directly, correcting the nit. For example, to flag an existing spelling error in `rfc1925.txt` (where "agglutinate" is misspelled as "aglutenate"), you would simply correct the word in the text:

```
   (5)  It is always possible to ***agglutinate*** multiple separate problems
        into a single complex interdependent solution. In most cases
        this is a bad idea.
```

When extracting the formatted review, such inline corrections are added to the "nits" section in "diff" format:

```
Section 2, paragraph 7, nit:
-    (5)  It is always possible to aglutenate multiple separate problems
-                                       ^
+    (5)  It is always possible to agglutinate multiple separate problems
+                                    +   ^
```

### Extracting the review

After editing a source file, you can extract a formatted review with:
``` shell
ietf-reviewtool review rfc1925.txt
```

With the given example, this would result in the following output:
```
-------------------------------------------------------------------------
COMMENT
-------------------------------------------------------------------------
Section 2, paragraph 2, comment:
Well, duh.

Section 2, paragraph 5, comment:
>    (3)  With sufficient thrust, pigs fly just fine. However, this is

Can we not always pick on pigs or pigeons?

-------------------------------------------------------------------------
NIT
-------------------------------------------------------------------------
Section 2, paragraph 7, nit:
-    (5)  It is always possible to aglutenate multiple separate problems
-                                       ^
+    (5)  It is always possible to agglutinate multiple separate problems
+                                    +   ^
```

## Acknowledgments

The ideas for some of these tools came from some of Henrik Levkowetz's earlier
`bash` scripts. In the case of the `strip` tool, most of the original regular
expressions were taken from his
[`rfcstrip`](https://tools.ietf.org/tools/rfcstrip/about) `awk` script.
