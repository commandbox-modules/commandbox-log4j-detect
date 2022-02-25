/**
* Scan all jars in folder recursivley for log4j vulns
* .
* Scan the current dir and all sub dirs for vulnerable Log4j jars
* {code}
* log4j-detect 
* {code}
*
* Scan a different dir for vulnerable Log4j jars
* {code}
* log4j-detect /path/to/dir
* {code}
*
* Scan a list of directories for vulnerable Log4j jars
* {code}
* log4j-detect C:/foo,C:/bar,D:/baz
* {code}
*
* Scan a all drives on your machine.  This can take a very long time.
* {code}
* log4j-detect --scanAllDrives
* {code}
*
* Force a re-download of the latest version of the scanner binary
* {code}
* log4j-detect C:/websites/ --forceBinaryDownload
* {code}
*
*/
component {
	property name="progressableDownloader" 	inject="ProgressableDownloader";
	property name="progressBar" 			inject="ProgressBar";

	/**
	* @directory List of absolute or relative paths to folder to look for jars
	* @scanAllDrives Set to true to scan the root of every drive on the machine.  When set to true, "directory" input is ignored. Warning, this can take a long time.
	* @forceBinaryDownload Set to true to force a re-download of the scanner binary
	*/
	function run(
		directory='',
		boolean scanAllDrives=false,
		boolean forceBinaryDownload=false
	) {
		var OSName = 'windows';
		if( fileSystemUtil.isMac() ) {
			OSName = 'darwin';
		} else if( fileSystemUtil.isLinux() ) {
			OSName = 'linux';
		}

		var CPUArch = 'amd';
		if( getSystemSetting( 'os.arch', '' ).findNoCase( 'arm' ) ) {
			CPUArch = 'arm';
		}

		var scannerFolder = expandPath( '/commandbox-log4j-detect/scanner' );
		if( forceBinaryDownload ) {
				print.line( 'Removing old scanner binary.' ).toConsole()
				directoryDelete( scannerFolder, true );
		}
		var tempFolder = expandPath( '/commandbox-log4j-detect/temp' );
		if( !directoryExists( scannerFolder ) ) {
			directoryCreate( tempFolder );
			directoryCreate( scannerFolder );
			try {
				
				print.line( 'Downloading the proper scan tool release for your OS and CPU.' ).toConsole()

				http url="https://api.github.com/repos/whitesource/log4j-detect-distribution/releases/latest" result="local.http";
				var releases = deserializeJSON( local.http.fileContent )
					.assets
					.map( (r)=>{
						return {
							'name':r.name.reReplaceNoCase( 'log4j-detect[_-][0-9]*\.[0-9]*\.[0-9]*[_-]', '' ),
							'downloadURL':r.browser_download_url
						};
					} )
					.filter( (r)=>!r.name.findNoCase( 'checksums' ) && !r.name.endsWith( '.deb' ) && !r.name.endsWith( '.rpm' ) );

				var myRelease = releases
					.filter( (r)=>r.name.findNoCase( OSName ) && r.name.findNoCase( CPUArch ) );

				if( myRelease.isEmpty() ) {
					print.line( 'Found releases are:' )
						.line( releases.map( (r)=>r.name ) )
					error( 'No suitable release found for your OS [#OSName#] and CPU [#CPUArch#].' )
				}
				myRelease = myRelease[1];

				var downloadFile = tempFolder & '/' & myRelease.name;
				progressableDownloader.download(
					myRelease.downloadURL,
					downloadFile,
					function( status ) {
						progressBar.update( argumentCollection = status );
					}
				);

				if( myRelease.name.endsWith( '.zip' ) ) {
					zip action="unzip" file="#downloadFile#" destination="#scannerFolder#" overwrite="true";
				} else if( myRelease.name.endsWith( '.tar.gz' ) ) {
					fileSystemUtil.extractTarGz( downloadFile, scannerFolder )
				} else {
					error( 'Unrecognized file format [#myRelease.name#]' );
				}
			
			} catch( any e ) {
				try { directoryDelete( scannerFolder, true ); } catch( any e ) { print.line( 'Could not delete [#scannerFolder#]' ); }
				rethrow;
			} finally {
				try { directoryDelete( tempFolder, true ); } catch( any e ) { print.line( 'Could not delete [#tempFolder#]' ); }
			}
		}

		var scannerFiles = directorylist( scannerFolder, false, 'query' ).filter( (p)=>p.type == 'file' && p.name.findNoCase( 'log4j-detect' )  );
		if( !scannerFiles.recordCount ) {
			error( 'Could not find scanner binary named "log4j-detect" in [#scannerFolder#].  Please delete this folder and try again to re-download.' );
		}
		var scannerBinary = scannerFiles.directory & '/' & scannerFiles.name;

		if( scanAllDrives ) {
			var directories = []
				.append( createObject( 'java', 'java.io.File' )
				.listRoots(), true )
				.map( (d)=>d.toString() );
		} else {
			var directories = directory
				.listToArray()
				.map( (d)=>resolvePath( d ) );
		}

		// Strip trailing slashes
		directories = directories.map( (d)=>{
			if( d.endsWith( '/' ) || d.endsWith( '\' ) && d != '/' ) {
				return d.left(-1);
			}
			return d;
		} )

		directories.each( (d)=>{
			print.line();
			var output = '';
			try { 
				output = command( 'run "#scannerBinary#"' )
					.params( 'scan -d "#d#" ' )
					.run( returnOutput=true );				
			} catch( any e ) {
				output = e.message;
				if( isJSON( e.extendedInfo ) ){
					var info = deserializeJSON( e.extendedInfo );
					if( info.keyExists( 'commandOutput' ) ) {
						output = info.commandOutput;
					}
				}
			}

			// Simplify the output if we only scanned one folder
			if( directories.len() == 1 ) {
				print
					.line( output.replaceNoCase( d, '.', 'all' ) );
			} else {
				print
					.line( output );
			}

			if( output.findNoCase( 'Vulnerable Files:' ) ) {
				setExitCode( 1 );
			}

		} );


			
	}

}
