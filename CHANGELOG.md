# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- RQL (Reflex Query Language)

## 21.11.0 - 2021-11-08

### Feature

- Added support for RQL (Reflex Query Language) when creating Event Rules and processing Event Rules against ingested Events.  More on RQL can be found [here](https://github.com/reflexsoar/reflex-docs/blob/main/rql.md)

### Bug Fix

- Fixed a bug when using a `Contains` statement in RQL when only a single mutator was given

## 21.11.0 - 2021-11-05

### Bug

- Fixed a bug where not all events were showing in an aggregated view and the events page was showing a small subset of the events instead of the proper page size

### Enhancements

- Removed the Event signature hashing event when pushing Events via the API. The expectation is that that API client will generate the signature
- Added `source_field` and `original_source_field` to Observables so they can be used in RQL rules
- Added a new configuration field to the Elasticsearch Input called `tag_fields`.  Source fields in this list will have their values derived as Event Tags
- Added a new configuration field to the Elasticsearch Input called `signature_fields`. Source fields in this list will be derived to an array and hashed to become the events signature.  If none are defined, the signature defaults to the title of the event.
- Agent now supports field aliases as defined in `field_mappings`.  Field aliases will take the place of `source_field` for use in the management console for writing RQL
- Agent supports new configuration field for Elasticsearch inputs called `lucene_filter` to allow for more granular targeting of data in the source index