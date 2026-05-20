Some examples.

## Scanning an RPM-based distro

Scanning the RHEL 10.0 x86_64 RPM release tree

``` shell
❯ time syfter scan /Volumes/Extra/dists/rhel-10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -p rhel -v 10.0
╭─────────────────────────────────────────────────────────────── Syfter Scan ────────────────────────────────────────────────────────────────╮
│ Scanning: /Volumes/Extra/dists/rhel-10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64                                  │
│ Product: rhel-10.0                                                                                                                         │
│ Mode: Server                                                                                                                               │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: directory
Found 13257 RPM files (11097 non-debug)
Using syft version: 1.40.0
Running: syft dir:/Volumes/Extra/dists/rhel-10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -o syft-json --source-name 
rhel-10.0 --source-version 10.0 --override-default-catalogers rpm-archive-cataloger
 ✔ Indexed file system                      /Volumes/Extra/dists/rhel-10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 
 ✔ Cataloged contents                                                      8fa27bc8a624bdb983b42e698df2cffdc01df57b6d5800bd7211e14a0d10d226 
   ├── ✔ Packages                        [13,257 packages]  
   ├── ✔ Executables                     [0 executables]  
   ├── ✔ File metadata                   [13,257 locations]  
   └── ✔ File digests                    [13,257 files]  
[0000]  WARN adding 'file' tag to the default cataloger selection, to override add '-file' to the cataloger selection request
Excluded 2160 debug packages (debuginfo/debugsource)
Excluded 2160 debug source files
Modified 11097 artifacts with product metadata
Preparing upload: 11097 packages, 6424406 files
Creating import job...
Job created: b3219bcf-78d6-482a-995a-eff0e678f625
Building TSV files...
TSV built: packages=401.4KB, files=215399.0KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (326474.9KB)...
  Uploading modified_sbom (240608.6KB)...
  Uploading packages_tsv (401.4KB)...
  Uploading files_tsv (215399.0KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #8 uploaded to server (job: b3219bcf-78d6-482a-995a-eff0e678f625)
syfter scan  -p rhel -v 10.0  404.93s user 55.27s system 60% cpu 12:40.05 total
```

## Scanning a container

When scanning containers, syfter automatically detects the base image and all layers to determine which image contributed each package.  Scanning the `go-toolset` container direct from the Red Hat Container Catalog:

``` shell
❯ time syfter scan registry.redhat.io/rhel9/go-toolset:1.25 \
  -p go-toolset -v 1.25 --source skopeo
╭─────────────────────────────────────────────────────────────── Syfter Scan ────────────────────────────────────────────────────────────────╮
│ Scanning: registry.redhat.io/rhel9/go-toolset:1.25                                                                                         │
│ Product: go-toolset-1.25                                                                                                                   │
│ Mode: Server                                                                                                                               │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: container
Pulling image with skopeo (linux/amd64)...
Image pulled successfully
Using syft version: 1.40.0
Running: syft oci-dir:/Users/redhat/tmp/syfter-rqq9xdhj/image -o syft-json --source-name go-toolset-1.25 --source-version 1.25
 ✔ Parsed image                                                     sha256:9e9d00aa4282077195e9700a4740bdf43555e79390afcb515b86226c8d2f5302 
 ✔ Cataloged contents                                                      682aab8265d43b7b9b34b556ea5cd17a587b2d259b9eee9e8ee88124de9764e1 
   ├── ✔ Packages                        [676 packages]  
   ├── ✔ Executables                     [1,283 executables]  
   ├── ✔ File metadata                   [21,666 locations]  
   └── ✔ File digests                    [21,666 files]  
Excluded 1 debug packages (debuginfo/debugsource)
Excluded 81 debug source files
Modified 675 artifacts with product metadata
Found 4 container layers
Packages with layer info: 675/675
Checking 9 candidate base images...
Verified image chain: ubi9/ubi → ubi9/s2i-core → ubi9/s2i-base → rhel9/go-toolset
Scanning base images to determine package provenance...
  Scanning: registry.redhat.io/ubi9/ubi:9.7-1767674301...
    Found 187 packages (187 new)
  Scanning: registry.redhat.io/ubi9/s2i-core:1-1767713898...
    Found 204 packages (17 new)
  Scanning: registry.redhat.io/ubi9/s2i-base:1-1768264882...
    Found 419 packages (215 new)
Determined source images for 624 packages
Packages with source image: 675/675
Preparing upload: 675 packages, 33614 files
Creating import job...
Job created: 75124798-f9ec-462d-92f5-2bd3c7a7da42
Building TSV files...
TSV built: packages=27.6KB, files=1148.9KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (3663.6KB)...
  Uploading modified_sbom (3647.2KB)...
  Uploading packages_tsv (27.6KB)...
  Uploading files_tsv (1148.9KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #2 uploaded to server (job: 75124798-f9ec-462d-92f5-2bd3c7a7da42)
syfter scan registry.redhat.io/rhel9/go-toolset:1.25 -p go-toolset -v 1.25    52.16s user 20.63s system 40% cpu 2:59.20 total
```

Now queries show the source image for each package:

``` shell
❯ time syfter query -n 'go%' -p go-toolset -v 1.25
                            Package Search Results                             
                                                                               
  Name                    Version          Product           Source Image      
 ───────────────────────────────────────────────────────────────────────────── 
  go-srpm-macros          3.6.0-12.el9_7   go-toolset-1.25   ubi9/s2i-base     
  go-toolset              1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  gobject-introspection   1.68.0-11.el9    go-toolset-1.25   ubi9/ubi          
  golang                  1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  golang-bin              1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  golang-race             1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  golang-src              1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
                                                                               
syfter query -n 'go%' -p go-toolset -v 1.25  0.16s user 0.04s system 80% cpu 0.249 total

❯ time syfter query -n '%git' -p go-toolset -v 1.25
                       Package Search Results                        
                                                                     
  Name          Version          Product           Source Image      
 ─────────────────────────────────────────────────────────────────── 
  @npmcli/git   6.0.3            go-toolset-1.25   rhel9/go-toolset  
  git           2.47.3-1.el9_6   go-toolset-1.25   ubi9/s2i-base     
                                                                     
syfter query -n '%git' -p go-toolset -v 1.25  0.15s user 0.04s system 90% cpu 0.206 total
```

This tells you that if you need to fix a vulnerability in `gobject-introspection`, you need to update the `ubi9/ubi` base image, not the `go-toolset` container itself.  Likewise, if you're looking to fix `git` it's in the intermediary `ubi9/s2i-base` container, not the base `ubi9/ubi` or the `go-toolset` container.

### Viewing the container layer chain

Use the `layers` command to see the complete layer chain for a container:

``` shell
❯ time syfter layers -p go-toolset -v 1.25 
╭────────────────────────────────────────────────────────── Container Layer Chain ───────────────────────────────────────────────────────────╮
│ Container: registry.redhat.io/rhel9/go-toolset:1.25                                                                                        │
│ Layers: 4                                                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                              
  #     Layer ID          Source Image       Version   Image Reference (copy/paste)                           
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────── 
  0     a6cca9262fdd6     ubi9/ubi           9.7       registry.redhat.io/ubi9/ubi:9.7-1767674301             
  1     efa697a554ff9     ubi9/s2i-core      1         registry.redhat.io/ubi9/s2i-core:1-1767713898          
  2     0ab3ef6ff04cf     ubi9/s2i-base      1         registry.redhat.io/ubi9/s2i-base:1-1768264882          
  3     45d7e18dbaad7     rhel9/go-toolset   1.25.3    registry.redhat.io/rhel9/go-toolset:1.25.3-1768393489  
                                                                                                              

Unique source images: 4
  • rhel9/go-toolset -> registry.redhat.io/rhel9/go-toolset:1.25.3-1768393489
  • ubi9/s2i-base -> registry.redhat.io/ubi9/s2i-base:1-1768264882
  • ubi9/s2i-core -> registry.redhat.io/ubi9/s2i-core:1-1767713898
  • ubi9/ubi -> registry.redhat.io/ubi9/ubi:9.7-1767674301
syfter layers -p go-toolset -v 1.25  0.15s user 0.04s system 91% cpu 0.210 total
```

This shows the complete image chain: `ubi9/ubi` → `ubi9/s2i-core` → `ubi9/s2i-base` → `rhel9/go-toolset`, with each layer attributed to the image that introduced it. The full image references include the exact version-release tags.

## Scanning a Middleware ZIP archive

Scanning the EAP 8.1 ZIP archive:

``` shell
❯ time syfter scan -p eap -v 8.1 /Volumes/Extra/dists/jboss-eap-8.1.0.zip 
╭─────────────────────────────────────────────────────────────── Syfter Scan ────────────────────────────────────────────────────────────────╮
│ Scanning: /Volumes/Extra/dists/jboss-eap-8.1.0.zip                                                                                         │
│ Product: eap-8.1                                                                                                                           │
│ Mode: Server                                                                                                                               │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: archive
Using syft version: 1.40.0
Running: syft /Volumes/Extra/dists/jboss-eap-8.1.0.zip -o syft-json --source-name eap-8.1 --source-version 8.1
 ✔ Indexed file system                                                                   /Users/redhat/tmp/syft-archive-contents-2278040947 
 ✔ Cataloged contents                                                      9b5ed0c66db9dbac8d01c3c13aa0fc7b3f0dc7a307b5d59d270897be990ddd43 
   ├── ✔ Packages                        [869 packages]  
   ├── ✔ Executables                     [7 executables]  
   ├── ✔ File metadata                   [674 locations]  
   └── ✔ File digests                    [674 files]  
Modified 869 artifacts with product metadata
Preparing upload: 869 packages, 0 files
Creating import job...
Job created: 6e9d8c30-6688-4a46-922d-7aec2467beee
Building TSV files...
TSV built: packages=33.0KB, files=0.0KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (689.1KB)...
  Uploading modified_sbom (654.4KB)...
  Uploading packages_tsv (33.0KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #3 uploaded to server (job: 6e9d8c30-6688-4a46-922d-7aec2467beee)
syfter scan -p eap -v 8.1 /Volumes/Extra/dists/jboss-eap-8.1.0.zip  11.72s user 6.58s system 160% cpu 11.413 total
```

## Scanning a Middleware JAR archive

Scanning the RHDM installer JAR archive:

``` shell
❯ time syfter scan -p rhdm -v 7.12.1 /Volumes/Extra/dists/rhdm-installer-7.12.1.jar 
╭─────────────────────────────────────────────────────────────── Syfter Scan ────────────────────────────────────────────────────────────────╮
│ Scanning: /Volumes/Extra/dists/rhdm-installer-7.12.1.jar                                                                                   │
│ Product: eap-8.1                                                                                                                           │
│ Mode: Server                                                                                                                               │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: file
Using syft version: 1.40.0
Running: syft /Volumes/Extra/dists/rhdm-installer-7.12.1.jar -o syft-json --source-name rhdm-7.12.1 --source-version 7.12.1
 ✔ Indexed file system                                                                       /Volumes/Extra/dists/rhdm-installer-7.12.1.jar 
 ✔ Cataloged contents                                                      fa9819fb01caa57d283c5112808129cb0b309aa677fb1021157505fa5adc4bb0 
   ├── ✔ Packages                        [124 packages]  
   ├── ✔ Executables                     [0 executables]  
   ├── ✔ File digests                    [1 files]  
   └── ✔ File metadata                   [1 locations]  
Modified 124 artifacts with product metadata
Preparing upload: 124 packages, 0 files
Creating import job...
Job created: b32d6afa-03c1-4120-b630-28c39abdc498
Building TSV files...
TSV built: packages=4.4KB, files=0.0KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (22.7KB)...
  Uploading modified_sbom (18.7KB)...
  Uploading packages_tsv (4.4KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #5 uploaded to server (job: b32d6afa-03c1-4120-b630-28c39abdc498)
syfter scan -p eap -v 8.1 /Volumes/Extra/dists/rhdm-installer-7.12.1.jar  3.85s user 0.98s system 56% cpu 8.580 total
```

## Searching for files

Searching for the `sshd` binary:

``` shell
❯ time syfter query -f '%sbin/sshd'  
                      File Search Results                       
                                                                
  Path             Package                           Product    
 ────────────────────────────────────────────────────────────── 
  /usr/sbin/sshd   openssh-server-0:9.9p1-7.el10_0   rhel-10.0  
                                                                
syfter query -f '%sbin/sshd'  0.18s user 0.05s system 7% cpu 3.266 total
```

Searching for `libzma.so`:

``` shell
❯ time syfter query -f '%liblzma.so' 
                                  File Search Results                                  
                                                                                       
  Path                    Package                     Product           Source Image   
 ───────────────────────────────────────────────────────────────────────────────────── 
  /usr/lib64/liblzma.so   xz-devel-5.2.5-8.el9_0      go-toolset-1.25   ubi9/s2i-base  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-3.el10     rhel-10.0                        
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-4.el10_0   rhel-10.0                        
                                                                                       
syfter query -f '%liblzma.so'  0.15s user 0.04s system 7% cpu 2.585 total
```

## Searching for packages

Searching for the `openldap` package:

``` shell
❯ time syfter query -n 'openldap'
                            Package Search Results                             
                                                                               
  Name       Version          Product                        Source Image      
 ───────────────────────────────────────────────────────────────────────────── 
  openldap   2.6.8-4.el9      multicluster-globalhub-1.4.3   ubi9/ubi-minimal  
  openldap   2.6.8-4.el9      go-toolset-1.25                ubi9/ubi          
  openldap   0:2.6.8-3.el10   rhel-10.0                                        
                                                                               
syfter query -n 'openldap'  0.15s user 0.04s system 82% cpu 0.222 total
```

## Statistics

See the statistics of what's in the database (and for reference, how big it is on-disk):

``` shell
❯ syfter stats                             
╭──────────────────────────────────────────────────────────────── Statistics ────────────────────────────────────────────────────────────────╮
│ Mode: Server                                                                                                                               │
│ Database: postgresql                                                                                                                       │
│ Storage: s3                                                                                                                                │
│ Products: 4                                                                                                                                │
│ Systems: 2                                                                                                                                 │
│ Scans: 6                                                                                                                                   │
│ Packages: 14573                                                                                                                            │
│ Files: 6577833                                                                                                                             │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Exporting SBOMs

Export the internal syft SBOM format from the database to all export formats:

``` shell
❯ time syfter export -p rhel -v 10.0 -f all -o output/
Converting to spdx-json...
Converting to spdx-tag-value...
Converting to cyclonedx-json...
Converting to cyclonedx-xml...
✓ Exported to 4 formats in output/
  output/rhel-10.0.spdx.json
  output/rhel-10.0.spdx
  output/rhel-10.0.cdx.json
  output/rhel-10.0.cdx.xml
syfter export -p rhel -v 10.0 -f all -o output/  539.71s user 30.52s system 93% cpu 10:07.88 total
```

## System Mode (Infrastructure Scanning)

Syfter can also be used to scan and track packages across your infrastructure.

### Scanning the Localhost

Scan the local host and tag it for grouping:

``` shell
❯ syfter system-scan --tag production
╭────────────────────────────── Syfter System Scan ──────────────────────────────╮
│ Scanning: localhost                                                               │
│ Hostname: webserver01.example.com                                                 │
│ IP: 192.168.1.50                                                                  │
│ OS: Linux 6.5.0-14-generic                                                        │
│ Tag: production                                                                   │
╰───────────────────────────────────────────────────────────────────────────────────╯
Scanning localhost (webserver01.example.com)...
Using syft version: 1.40.0
...
✓ System scan #1 uploaded to server (job: abc123...)
```

### Scanning a Remote Host via SSH

Scan a remote host by providing the hostname or IP.  It does use SSH (Syft is used to make these connections).

``` shell
❯ time syfter system-scan git.annvix.ca --tag personal -u vdanen
Getting info from remote host git.annvix.ca...
╭──────────────────────────────────────────────────────────── Syfter System Scan ────────────────────────────────────────────────────────────╮
│ Scanning: git.annvix.ca                                                                                                                    │
│ Hostname: git.annvix.ca                                                                                                                    │
│ IP: 192.168.250.22                                                                                                                         │
│ OS: Linux 6.18.2-0-virt                                                                                                                    │
│ Tag: personal                                                                                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Connecting to vdanen@git.annvix.ca...
Remote syft version: 1.38.0
Running remote scan on git.annvix.ca...
Remote scan complete
Modified 1169 artifacts with product metadata
Preparing upload: 1169 packages, 27610 files
Creating system import job...
Job created: 67ee62fb-0a51-45fb-bd8d-e3c68928cec3
Building TSV files...
TSV built: packages=34.3KB, files=700.3KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (2547.6KB)...
  Uploading modified_sbom (2524.2KB)...
  Uploading packages_tsv (34.3KB)...
  Uploading files_tsv (700.3KB)...
Starting import job...
Processing in background, polling for status...
✓ System scan #4 uploaded to server (job: 67ee62fb-0a51-45fb-bd8d-e3c68928cec3)
syfter system-scan git.annvix.ca --tag personal -u vdanen  3.00s user 0.24s system 18% cpu 17.451 total
```

### Listing Systems

View all scanned systems:

``` shell
❯ syfter systems
                                                   Systems                                                    
                                                                                                              
  Hostname         IP               Tag        OS                             Packages    Files   Last Scan   
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────── 
  git.annvix.ca    192.168.250.22   personal   Linux 6.18.2-0-virt                1169   27,610   2026-01-14  
  plex.annvix.ca   192.168.250.20   personal   Linux 6.17.9-300.fc43.x86_64       1275   89,296   2026-01-15 
```

### Querying Packages Across Systems

Find which systems have a specific package installed:

``` shell
❯ syfter system-query -n 'openssh-server'
                System Package Search Results                 
                                                              
  Name             Version         System           Tag       
 ──────────────────────────────────────────────────────────── 
  openssh-server   10.2_p1-r0      git.annvix.ca    personal  
  openssh-server   10.0p1-6.fc43   plex.annvix.ca   personal  
```

### Filtering by Tag

Find packages only in personal systems:

``` shell
❯ syfter system-query -n 'kernel' -t personal 
              System Package Search Results              
                                                         
  Name     Version            System           Tag       
 ─────────────────────────────────────────────────────── 
  kernel   6.17.12-300.fc43   plex.annvix.ca   personal  
  kernel   6.17.8-300.fc43    plex.annvix.ca   personal  
  kernel   6.17.9-300.fc43    plex.annvix.ca   personal 
```

### Listing Packages for a Specific System

``` shell
❯ syfter system-list -H plex.annvix.ca -t packages | head -20
ModemManager-1.24.2-1.fc43
ModemManager-glib-1.24.2-1.fc43
NetworkManager-1:1.54.3-2.fc43
NetworkManager-bluetooth-1:1.54.3-2.fc43
...
```

### Finding Files Across Systems

Search for specific files across your infrastructure:

``` shell
❯ syfter system-query -f '%bin/sshd'
                         System File Search Results                          
                                                                             
  Path             Package                        System           Tag       
 ─────────────────────────────────────────────────────────────────────────── 
  /usr/bin/sshd    openssh-server-10.0p1-6.fc43   plex.annvix.ca   personal  
  /usr/sbin/sshd   openssh-server-10.2_p1-r0      git.annvix.ca    personal 
```