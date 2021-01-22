# *TODO: Make decision*

Technical Story: https://github.com/theupdateframework/tuf/pull/1223
in particular [this PR discussion](https://github.com/theupdateframework/tuf/pull/1223#issuecomment-737188686).

## Context and Problem Statement
In the course of implementing a class-based role metadata model we have also
reviewed options on how to design de/serialization infrastructure between wire
formats and the class model. In an initial attempt we have implemented
de/serialization on the metadata class (see considered option 1), but issues
with inheritance and calls for more flexibility have caused us to rethink this
approach.

## Decision Drivers
* A class-based role metadata model (see ADR 0004) requires de/serialization
  routines from and to wire formats
* TUF integrators may choose custom de/serialization implementations to support
  custom wire formats
* Readability and simplicity of code are important

## Considered Options
1. De/serialization on metadata classes
2. De/serialization on metadata subclasses
3. De/serialization separated
4. Compromise: Default dict/json de/serialization on metadata base classes,
   with the option to override using a custom de/serialization implementation

## Decision Outcome
*TODO: Make and describe the decision*

## Pros and Cons of the Options

### De/serialization on metadata classes
* Good, because de/serialization for any object is encapsulated within the
  corresponding class and thus structured in small code chunks, using the
  already existing hierarchical class model structure.

* Good, because we can use dedicated factory methods alongside constructors for
  deserialization to cleanly separate deserialization from object instantiation.

* Bad, because the class model should be completely decoupled from the wire
  format in order to facilitate the use of custom de/serialization
  implementations.

* Bad, because it gets complicated with inheritance in the class model.

### De/serialization on metadata subclasses
* Good, because wire format de/serialization is decoupled from base classes.
* Bad, because a users needs to decide on de/serialization ahead of time, e.g.
  by instantiating concrete `JsonMetadata` or `CborMetadata`, etc. objects.

### De/serialization separated
* Good, because wire format de/serialization is completely decoupled from class
  model, thus repository or client code can more easily account for custom
  de/serialization implementations.

* Bad, because a decoupled de/serialization implementation needs to
  "re-implement" the entire class hierarchy, likely in a procedural manner.

## Links
* [ADR 0004: Add classes for complex metadata attributes (decision driver)](/Users/lukp/tuf/tuf/docs/adr/0004-extent-of-OOP-in-metadata-model.md)
* [PR: Add simple TUF role metadata model (option 1)](https://github.com/theupdateframework/tuf/pull/1112)
  * [details about separation of de/serialization and instantiation](https://github.com/theupdateframework/tuf/commit/f63dce6dddb9cfbf8986141340c6fac00a36d46e)
  * [code comment about issues with inheritance](https://github.com/theupdateframework/tuf/blob/9401059101b08a18abc5e3be4d60e18670693f62/tuf/api/metadata.py#L297-L306)
* [SSLIB/Issue: Add metadata container classes (comparison of options 1 and 2)](https://github.com/secure-systems-lab/securesystemslib/issues/272)
* [tuf-on-a-plane parser (option 3)](https://github.com/trishankatdatadog/tuf-on-a-plane/blob/master/src/tuf_on_a_plane/parsers/)
