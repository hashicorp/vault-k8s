# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

binary {
	go_stdlib  = true // Scan the Go standard library used to build the binary.
	go_modules = true // Scan the Go modules included in the binary.
	osv        = true // Use the OSV vulnerability database.
	oss_index  = true // And use OSS Index vulnerability database.

	secrets {
		all = true
	}
}

container {
	dependencies = true // Scan any installed packages for vulnerabilities.
	osv          = true // Use the OSV vulnerability database.

	secrets {
		all = true
	}
}
