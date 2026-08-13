package main

import "testing"

func TestCVEWindowsChunks120Days(t *testing.T) {
	windows, err := cveWindows("2024-01-01T00:00:00.000", "2024-12-31T00:00:00.000")
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 4 {
		t.Fatalf("a ~365 day range must split into 4 windows of <=119 days, got %d", len(windows))
	}
	if windows[0].start != "2024-01-01T00:00:00.000" {
		t.Fatalf("first window must start at since, got %q", windows[0].start)
	}
	if windows[len(windows)-1].end != "2024-12-31T00:00:00.000" {
		t.Fatalf("last window must end at until, got %q", windows[len(windows)-1].end)
	}
	for i := 1; i < len(windows); i++ {
		if windows[i].start != windows[i-1].end {
			t.Fatalf("windows must be contiguous: %q != %q", windows[i].start, windows[i-1].end)
		}
	}
}

func TestCVEWindowsRejectsBadRange(t *testing.T) {
	if _, err := cveWindows("2024-12-31T00:00:00.000", "2024-01-01T00:00:00.000"); err == nil {
		t.Fatal("until before since must error")
	}
	if _, err := cveWindows("not-a-date", ""); err == nil {
		t.Fatal("bad since must error")
	}
}
