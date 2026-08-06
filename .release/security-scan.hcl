# Copyright IBM Corp. 2019, 2026
# SPDX-License-Identifier: MPL-2.0

binary {
	go_stdlib  = true // Scan the Go standard library used to build the binary.
	go_modules = true // Scan the Go modules included in the binary.
	osv        = true // Use the OSV vulnerability database.
	oss_index  = true // And use OSS Index vulnerability database.

	secrets {
		all = true
	}

	triage {
		suppress {
			vulnerabilities = [
				// GO-2026-5932: golang.org/x/crypto/openpgp is flagged as unmaintained
				// and unsafe by design. There is no fixed version — the advisory covers
				// all versions (introduced: 0, no fixed event). vault-k8s does not
				// import openpgp directly; it is pulled in transitively but never
				// called at runtime. Suppressed until upstream removes the package
				// or a transitive dependency drops it.
				"GO-2026-5932",
			]
		}
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
