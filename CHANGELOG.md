# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)

<!--
## [<exact release including patch>](<github compare url>) - <release date in YYYY-MM-DD>
### Added
  - <summary of new features>

### Changed
  - <for changes in existing functionality>

### Deprecated
  - <for soon-to-be removed features>

### Removed
  - <for now removed features>

### Fixed
  - <for any bug fixes>

### Security
  - <in case of vulnerabilities>
-->

## [Unreleased](https://github.com/cyverse/rtwo/compare/0.5.22...HEAD) - YYYY-MM-DD
### Changed
  - Change ex_list_all_instances to fetch next page until no remaining results
    ([#32](https://github.com/cyverse/rtwo/pull/32))

## [0.5.22](https://github.com/cyverse/rtwo/compare/0.5.21...0.5.22) - 2018-08-02
### Changed
  - Change ex_list_all_instances performs manual pagination, doesn't rely on
    optional servers_links ([#31](https://github.com/cyverse/rtwo/pull/31))

## [0.5.21](https://github.com/cyverse/rtwo/compare/0.5.20...0.5.21) - 2018-06-29
### Fixed
  - The incorrect version (0.5.19) of rtwo was was uploaded to pypi as 0.5.20.
    The changes originally intended for 0.5.20 were re-uploaded as 0.5.21

## [0.5.20](https://github.com/cyverse/rtwo/compare/0.5.19...0.5.20) - 2018-06-19
### Changed
  - Allow external network to be explicitly passed to `associate_floating_ip`
    ([#27](https://github.com/cyverse/rtwo/pull/27))

## [0.5.19](https://github.com/cyverse/rtwo/compare/0.5.18...0.5.19) - 2018-04-26
### Fixed
  - Fix unintentional fetch of all_tenants instances
    ([#25](https://github.com/cyverse/rtwo/pull/25))
