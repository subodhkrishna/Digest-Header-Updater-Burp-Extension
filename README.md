# Digest-Header-Updater-Burp-Extension

This Burp Suite extension updates the Digest Header value based on the changes made to POST or PUT body payload.

Some application have a HTTP header which contains the digest value of the request body payload. If request body is modified and the digest header value is not updated the server returns an error. Thsi extension can be used in the session handeling rules to update the digest header value.
