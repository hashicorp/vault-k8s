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

	triage {
		suppress {
			// The OSV scanner will trip on several packages that are included in the
			// the UBI images. This is due to RHEL using the same base version in the
			// package name for the life of the distro regardless of whether or not
			// that version has been patched for security. Rather than enumate ever
			// single CVE that the OSV scanner will find (several tens) we'll ignore
			// the base UBI packages.
			paths = [
				"usr/lib/sysimage/rpm/*",
				"var/lib/rpm/*",
			]
		}
	}
}
