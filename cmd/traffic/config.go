package main

import "time"

var requestLimit = 256 << 10
var responseLimit = 64 << 10
var diskLimitMiB = 2048
var retention = 24 * time.Hour
var scanWindow = time.Minute
var scanThreshold = 20

var capturePorts = map[int]bool{80: true, 443: true}

var iisProbe, iisRuntime string
var iisPython = "python"
