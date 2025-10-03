# moonbasepp

### A framework agnostic minimal moonbase.sh licensing library

## About
[moonbase.sh](https://moonbase.sh/) provide SDKs for various languages & frameworks - C++ side though, this is limited to their JUCE module.

The goal of this library then, is to provide a relatively painless abstraction layer over the raw POST/GET calls to the moonbase api, for you to ingest & handle in a C++ environment of your choosing.

It was written out of necessity for one of our work-in-progress plugins for SLM Audio (which is under some time pressure at the moment) and as such, we haven't (yet) gotten around to providing unit tests, or linux support for that matter. On that note, any MRs are welcomed!

One other thing to note is that we don't provide any threading mechanism to call these functions, that's left up to your implementation - however, we've documented guidelines on what threads functions in `moonbase_Licensing.h` are expected to be called on; TLDR, threading-not-included.


## Usage
### Building
moonbasepp is built via CMake, and will compile a static library for you to link to. We've only really tested consumption via FetchContent, ala 

```cmake
include(FetchContent)
FetchContent_Declare(moonbasepp 
    GIT_REPOSITORY git@github.com:SLM-Audio/moonbasepp.git
    GIT_SHALLOW ON 
    GIT_TAG v0.0.1
)
FetchContent_Declare(moonbasepp)
```

Once available, you can then link to `slma::moonbasepp`.

### API

The only file you'll really need to include yourself is `moonbasepp/moonbasepp_Licensing.h`. The doc comments in the header should be relatively self explanatory, and at some point once I have some more time, I do plan on hosting the docs on Doxygen; Until then though, use the source!

## Dependencies

We went out of our way to ensure that however gnarly and however much pain it caused us, the dependencies were all handled by our CMakeLists. These differ slightly on Windows and macOS, due to a few platform specific quirks. 

Really the nightmare dependency here is libcurl, which is transitively a dependency via [CPR](https://github.com/libcpr/cpr) - if you're on macOS this isn't really a concern, it already ships with your operating system. 
On *windows* this is an altogether different story - cpr does provide helpers to download and build curl (statically) if not found, but that in turn introduces a dependency on libpsl, which cpr are inexplicably building using... meson?
So that adds a dependency on *meson*, which is installed via *pip* (I know I know I know) - we do handle this in `cmake/meson.cmake`, but it does require a systemwide installation of python3 (expressed by our tersely worded "Python 3 is required" cmake error if it's not found). 

Obviously I am not *thrilled* about the above, and [Trémus](https://github.com/Tremus) of exacoustics fame has since sent a [vastly more minimal web-request option](https://github.com/Tremus/awesome-audio-plugin-framework/tree/master/examples/https_xrequest). So in future, expect us to move over to that, and send the curl / psl / meson/ python dependency to the shadow realm where it belongs.


## Compatibility 

moonbasepp requires C++20, and currently only works on Windows via MSVC, and macOS (minimum 10.15). I'd love to support more compilers and yknow, Linux, but for now those are the options - as mentioned earlier, if you want to see more support, open an MR!



