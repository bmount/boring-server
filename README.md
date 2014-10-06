# Boring Server


I would kind of like server for a:


-  mostly static site
-  with the ability to serve parts to trusted contributors ('admins', oneself) or
    other authenticated users assigned arbitrary 'trust' values
-  and that can hand off optionally authenticated requests to things
    like CouchDB, or proxy particular urls to little experiments in whatever language,
    or let trusted users see the admin panel of some nice http service, without having to
    come up with all new everything
-  and that has practically no server or database administration or configuration and
    is robust to all kinds of neglect and prolonged indifference to its continued operation


The first piece is the auth stuff. My first wish was to be able to do this:


```go
    http.Handle("/", http.FileServer(http.Dir(staticSiteDirectory)))
    
    http.Handle("/admin/", auth.Wrap(HandlerB, auth.Rule{Admin: true}))
```


It's experimental. Planned work includes a simple UI for uploading files and doing layout and
content work.

Python is required for 1 or 2 of the tests.


License: MIT
