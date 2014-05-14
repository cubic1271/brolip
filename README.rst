======================================
Bro Log Information Processor (BroLIP)
======================================

Motivational Blurb
>>>>>>>>>>>>>>>>>>

The Bro logging library started as a kind of universal translator for btest.  Since it would be nice if new logging formats could re-use existing btests, we decided to put together a kind of universal translator for bro log files.  However, as the library matured a bit, it became evident that this kind of library could be very useful for bro users / developers when performing nontrivial post-processing and analysis of bro log files.  We spent a little bit of time documenting this code and making sure it would be reasonably straightforward to extend to support e.g. SQL, and viola!  We had a library.

Vital Statistics
>>>>>>>>>>>>>>>>

This library is written in Python.  We have tested the library with 2.6+ and it seems to work.  The library abuses list comprehensions, so anything less than Python 2.5 **should not** work with this library.

At the moment, this library supports:

* Sampling; skip rows to trade processing time for accuracy
* Filters: only pull out rows that fulfill certain criteria (a user-defined function)
* Multiple Logfiles: seamless loading / processing of an entire directory's worth of log files
* Compressed Logs: support for gzip / bzip2

The library was designed to be (in order of relative priority):

* **Easy to use** -- Process bro log files in relatively few lines of code

* **Easy to extend to support future log formats** -- Add a new file to the library, and possibly a new entry into __init__.py

* **Reasonably quick** -- We've done our best to abuse itertools, map(), filter(), and list comprehensions where possible to make the library pretty quick.  We do sacrifice readability in a few places to make the code faster; BroLogGenerator.py, in particular, can be kind of nasty in places.

What's In This Guide
>>>>>>>>>>>>>>>>>>>>

1. Quick Start (By Example)
2. Credits / Notes

Quick Start (By Example)
>>>>>>>>>>>>>>>>>>>>>>>>

So, first thing, let's write a bit of code that will open a single log file and print all the connection timestamps.::

    from brolog.BroLogManager import SimpleLogManager
    
    manager = SimpleLogManager()
    manager.load("a.log")     # or a.log.gz or a.log.bz2
    for e in manager:
        print "Connection at %s" % e['ts']

So, what is that doing?  Well...

1. We build a new SimpleLogManager (utility class for opening a *single logfile*; a little less work than the more generic log manager, but also slightly less capable as a result)
2. We load the log file we'd like to read
    * NOTE: This file **must** contain appropriate headers in order for the library to successfully load the file.
3. For each line in the log file, we print the 'ts' field.

Simple, yeah?

Okay, now that we've gotten something basic, let's add a *filter*.  A filter is a function which takes a single argument (an 'entry') and returns True or False.  For example::

    def myFilter(entry):
        return (entry['ts'] < 100)  # Look for antique packets

So, how would we apply the above filter to our log file?  Like so: ::

    from brolog.BroLogManager import SimpleLogManager
    
    def myFilter(entry):
        return (entry['ts'] < 100)  # Look for antique packets

    manager = SimpleLogManager()
    manager.load("a.log")     # or a.log.gz or a.log.bz2
    manager.set_filter(myFilter)
    for e in manager:
        print "Connection at %s" % e['ts']

Notice the 'set_filter' call there?  That sets a function to apply to every individual row read from the log file; if the filter returns true, then the row is produced as the next row in the log file.  In this case, we would print the timestamp for every log event tagged as occurring less than 100 secods after the dawn of UNIX time.

**NOTE**: In general, filters need to involve relatively little processing; they are applied to *every* row of a log file.

Now that we've covered filtered, let's take a second to cover statistics.  This library has some built-in support for basic statistics; while calculating them yourself isn't especially difficult, the library includes a special code path to help make this kind of thing faster.  Anyway, since I promised code, let's find the five most frequent response ports::

    from brolog.BroLogManager import SimpleLogManager
    
    def myFilter(entry):
        return (entry['ts'] < 100)  # Look for antique packets

    manager = SimpleLogManager()
    manager.load("a.log")     # or a.log.gz or a.log.bz2
    manager.set_filter(myFilter)
    for e in manager:
        print "Connection at %s" % e['ts']

    print 'Top 5 id.resp_p entries:'
    for x in xrange(min(5, len(manager.get().get_stats('id.resp_p')) )):
        print str(manager.get().get_stats('id.resp_p').get_index(x)),
    print ''

Okay, a few notes here:

* manager.get() is an ugliness that will hopefully be disappearing soon.  This gets the BroLogGenerator object from the manager.
* get_stats() is the entry point for all things statistics-related.  Given a field, this function will return type-specific statistics.

    * The exact mechanism by which statistics are computed depends on the field's *type*.
    * In this case, we were dealing with 'port' fields, so the library assumed we wanted to calculate grouping statistics (accumulate per unique item).
    * For more information, see BroAccumulator.py

* get_index() will return the Xth entry, ordered from most frequently encountered entry to least.  In the above example, the 0th entry would be the most frequent response port.

Instead of a grouping statistic, let's take a look at a math-ish statistic now::

    from brolog.BroLogManager import SimpleLogManager
    
    def myFilter(entry):
        return (entry['ts'] < 100)  # Look for antique packets

    manager = SimpleLogManager()
    manager.load("a.log")     # or a.log.gz or a.log.bz2
    manager.set_filter(myFilter)
    for e in manager:
        print "Connection at %s" % e['ts']

    print manager.get().get_stats('orig_bytes')

This will print some vital statistics about the orig_bytes field found in 'a.log' (min, max, average, and standard deviation).  Note that these fields can be accessed directly::

    manager.get().get_stats('orig_bytes').mean
    manager.get().get_stats('orig_bytes').max
    manager.get().get_stats('orig_bytes').min

... and so on.

Credits / Notes
>>>>>>>>>>>>>>>

Just a quick acknowledgment / thank you to Gregor Maier for his contributions / improvements to the code and the interface.

