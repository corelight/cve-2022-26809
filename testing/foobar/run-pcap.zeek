# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log

event zeek_done()
	{
	print "Goodbye world!";
	}
