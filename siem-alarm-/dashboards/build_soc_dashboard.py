#!/usr/bin/env python3
"""Build and validate the import-ready SIEM Alarm SOC Saved Objects bundle.

The generated NDJSON targets the legacy aggregation-based visualization schema
supported by OpenSearch Dashboards 2.19.x / Wazuh Dashboard 4.14.7.  Object IDs
are deterministic so an operator can audit collisions and perform controlled
upgrades.  The script uses only the Python standard library and remains
compatible with Python 3.8.
"""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "siem_alarm_template_final.json"
OUTPUT_PATH = Path(__file__).resolve().parent / "siem_alarm_soc_dashboard.ndjson"
MANIFEST_PATH = Path(__file__).resolve().parent / "siem_alarm_soc_dashboard.manifest.json"
EXPORT_REQUEST_PATH = Path(__file__).resolve().parent / "siem_alarm_soc_dashboard.export-request.json"

BUNDLE_VERSION = "1.1.0"
DATA_VIEW_ID = "siem-alarm-soc-v1-data-view"
DATA_VIEW_TITLE = "siem-alarm-*"
TIME_FIELD = "timestamp"

STATE = 'document.type: "alarm_state"'
FINALIZED_STATE = STATE + ' and alarm.status: "finalized"'
PRIORITY_STATE = STATE + ' and (risk.level: "High" or risk.level: "Critical")'
CRITICAL_STATE = STATE + ' and risk.level: "Critical"'
ESCALATION = 'document.type: "alarm_escalation"'
MULTI_IP_STATE = STATE + " and source_observed.srcip_unique_count > 1"
ASSET_GAP_STATE = STATE + ' and asset.source: "default"'

RISK_COLORS = {
    "Information": "#6092C0",
    "Low": "#2F9D98",
    "Medium": "#F5A700",
    "High": "#E7664C",
    "Critical": "#BD271E",
}

MIGRATION_VERSIONS = {
    "index-pattern": "7.6.0",
    "search": "7.9.3",
    "visualization": "7.10.0",
    "dashboard": "7.9.3",
}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def saved_object(object_type, object_id, attributes, references=None):
    return {
        "attributes": attributes,
        "id": object_id,
        "migrationVersion": {object_type: MIGRATION_VERSIONS[object_type]},
        "references": references or [],
        "type": object_type,
    }


def flatten_mapping_fields(properties, prefix=""):
    """Return (field name, OpenSearch type) pairs, including multi-fields."""
    result = []
    for name in sorted(properties):
        definition = properties[name]
        field_name = "%s.%s" % (prefix, name) if prefix else name
        field_type = definition.get("type")
        if field_type and field_type not in ("object", "nested"):
            result.append((field_name, field_type))
        for multi_name, multi_definition in sorted(definition.get("fields", {}).items()):
            multi_type = multi_definition.get("type")
            if multi_type:
                result.append((field_name + "." + multi_name, multi_type))
        if "properties" in definition:
            result.extend(flatten_mapping_fields(definition["properties"], field_name))
    return result


def data_view_field_type(opensearch_type):
    if opensearch_type in ("keyword", "text"):
        return "string"
    if opensearch_type in ("byte", "short", "integer", "long", "half_float", "float", "double"):
        return "number"
    if opensearch_type in ("date", "date_nanos"):
        return "date"
    if opensearch_type == "boolean":
        return "boolean"
    if opensearch_type == "ip":
        return "ip"
    return "string"


def build_data_view(template):
    properties = template["template"]["mappings"]["properties"]
    fields = [
        {
            "count": 0,
            "name": "_id",
            "type": "string",
            "scripted": False,
            "searchable": False,
            "aggregatable": False,
            "readFromDocValues": False,
        },
        {
            "count": 0,
            "name": "_index",
            "type": "string",
            "scripted": False,
            "searchable": False,
            "aggregatable": False,
            "readFromDocValues": False,
        },
        {
            "count": 0,
            "name": "_score",
            "type": "number",
            "scripted": False,
            "searchable": False,
            "aggregatable": False,
            "readFromDocValues": False,
        },
        {
            "count": 0,
            "name": "_source",
            "type": "_source",
            "scripted": False,
            "searchable": False,
            "aggregatable": False,
            "readFromDocValues": False,
        },
        {
            "count": 0,
            "name": "_type",
            "type": "string",
            "scripted": False,
            "searchable": False,
            "aggregatable": False,
            "readFromDocValues": False,
        },
    ]
    for name, opensearch_type in flatten_mapping_fields(properties):
        aggregatable = opensearch_type != "text"
        fields.append(
            {
                "count": 0,
                "name": name,
                "type": data_view_field_type(opensearch_type),
                "esTypes": [opensearch_type],
                "scripted": False,
                "searchable": True,
                "aggregatable": aggregatable,
                "readFromDocValues": aggregatable,
            }
        )
    attributes = {
        "fields": compact(fields),
        "fieldFormatMap": "{}",
        "timeFieldName": TIME_FIELD,
        "title": DATA_VIEW_TITLE,
    }
    return saved_object("index-pattern", DATA_VIEW_ID, attributes)


def index_reference():
    return {
        "id": DATA_VIEW_ID,
        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "type": "index-pattern",
    }


def search_source(query, discover=False):
    value = {
        "filter": [],
        "query": {"language": "kuery", "query": query},
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }
    if discover:
        value.update({"highlightAll": True, "version": True})
    return compact(value)


def build_search(object_id, title, description, query, columns, sort):
    attributes = {
        "columns": columns,
        "description": description,
        "hits": 0,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query, discover=True)},
        "sort": sort,
        "title": title,
        "version": 1,
    }
    return saved_object("search", object_id, attributes, [index_reference()])


def build_visualization(object_id, title, description, vis_state, query=None, ui_state=None):
    if query is None:
        source_json = "{}"
        references = []
    else:
        source_json = search_source(query)
        references = [index_reference()]
    attributes = {
        "description": description,
        "kibanaSavedObjectMeta": {"searchSourceJSON": source_json},
        "title": title,
        "uiStateJSON": compact(ui_state or {}),
        "version": 1,
        "visState": compact(vis_state),
    }
    return saved_object("visualization", object_id, attributes, references)


def metric_visualization(object_id, title, description, query, agg_type="count", field=None, subtext=""):
    agg_params = {} if field is None else {"field": field}
    vis_state = {
        "title": title,
        "type": "metric",
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": subtext,
                    "fontSize": 42,
                },
            },
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": agg_type,
                "schema": "metric",
                "params": agg_params,
            }
        ],
    }
    return build_visualization(object_id, title, description, vis_state, query)


def pie_filters_visualization(object_id, title, description, query, filters, colors):
    filter_values = [
        {"input": {"query": filter_query, "language": "kuery"}, "label": label}
        for label, filter_query in filters
    ]
    vis_state = {
        "title": title,
        "type": "pie",
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "filters",
                "schema": "segment",
                "params": {"filters": filter_values},
            },
        ],
    }
    return build_visualization(
        object_id,
        title,
        description,
        vis_state,
        query,
        {"vis": {"colors": colors}},
    )


def pie_terms_visualization(object_id, title, description, query, field, size=5, colors=None):
    vis_state = {
        "title": title,
        "type": "pie",
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": field,
                    "otherBucket": False,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                    "size": size,
                    "order": "desc",
                    "orderBy": "1",
                },
            },
        ],
    }
    ui_state = {"vis": {"colors": colors}} if colors else {}
    return build_visualization(object_id, title, description, vis_state, query, ui_state)


def area_time_visualization(
    object_id,
    title,
    description,
    query,
    metric_type="count",
    metric_field=None,
    split_field=None,
    split_size=5,
    colors=None,
):
    metric_params = {} if metric_field is None else {"field": metric_field}
    aggs = [
        {
            "id": "1",
            "enabled": True,
            "type": metric_type,
            "schema": "metric",
            "params": metric_params,
        },
        {
            "id": "2",
            "enabled": True,
            "type": "date_histogram",
            "schema": "segment",
            "params": {
                "field": TIME_FIELD,
                "interval": "auto",
                "min_doc_count": 1,
                "extended_bounds": {},
            },
        },
    ]
    if split_field:
        aggs.append(
            {
                "id": "3",
                "enabled": True,
                "type": "terms",
                "schema": "group",
                "params": {
                    "field": split_field,
                    "otherBucket": False,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                    "size": split_size,
                    "order": "desc",
                    "orderBy": "1",
                },
            }
        )
    vis_state = {
        "title": title,
        "type": "area",
        "params": {
            "type": "area",
            "grid": {"categoryLines": False, "style": {"color": "#eee"}},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "truncate": 100},
                    "title": {"text": "Time"},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": "Value"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "area",
                    "mode": "stacked" if split_field else "normal",
                    "data": {"label": "Value", "id": "1"},
                    "drawLinesBetweenPoints": True,
                    "showCircles": True,
                    "interpolate": "linear",
                    "valueAxis": "ValueAxis-1",
                }
            ],
            "addTooltip": True,
            "addLegend": bool(split_field),
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
        "aggs": aggs,
    }
    ui_state = {"vis": {"colors": colors}} if colors else {}
    return build_visualization(object_id, title, description, vis_state, query, ui_state)


def horizontal_terms_visualization(
    object_id, title, description, query, field, metric_type="count", metric_field=None, size=10
):
    metric_params = {} if metric_field is None else {"field": metric_field}
    vis_state = {
        "title": title,
        "type": "horizontal_bar",
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False, "style": {"color": "#eee"}},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 180},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": "Value"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "normal",
                    "data": {"label": "Value", "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True,
                    "showCircles": True,
                }
            ],
            "addTooltip": True,
            "addLegend": False,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": metric_type,
                "schema": "metric",
                "params": metric_params,
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": field,
                    "otherBucket": False,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                    "size": size,
                    "order": "desc",
                    "orderBy": "1",
                },
            },
        ],
    }
    return build_visualization(object_id, title, description, vis_state, query)


def markdown_visualization(object_id, title, markdown):
    vis_state = {
        "title": title,
        "type": "markdown",
        "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": markdown},
        "aggs": [],
    }
    return build_visualization(object_id, title, "Operator context and counting semantics.", vis_state)


def panel(panel_index, object_type, object_id, x, y, w, h):
    return {
        "gridData": {"w": w, "h": h, "x": x, "y": y, "i": str(panel_index)},
        "version": "2.19.5",
        "panelIndex": str(panel_index),
        "embeddableConfig": {},
        "panelRefName": "panel_%d" % (panel_index - 1),
        "_object_type": object_type,
        "_object_id": object_id,
    }


def build_dashboard(object_id, title, description, panels, time_from="now-24h"):
    panel_json = []
    references = []
    for item in panels:
        item = dict(item)
        object_type = item.pop("_object_type")
        referenced_id = item.pop("_object_id")
        references.append(
            {"id": referenced_id, "name": item["panelRefName"], "type": object_type}
        )
        panel_json.append(item)
    attributes = {
        "description": description,
        "hits": 0,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": compact(
                {
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "highlightAll": True,
                    "version": True,
                }
            )
        },
        "optionsJSON": compact(
            {"darkTheme": False, "useMargins": True, "hidePanelTitles": False}
        ),
        "panelsJSON": compact(panel_json),
        "refreshInterval": {"display": "5 minutes", "pause": False, "value": 300000},
        "timeFrom": time_from,
        "timeRestore": True,
        "timeTo": "now",
        "title": title,
        "version": 1,
    }
    return saved_object("dashboard", object_id, attributes, references)


def build_records(template):
    records = [build_data_view(template)]

    records.extend(
        [
            build_search(
                "siem-alarm-soc-v1-search-priority",
                "SIEM Alarm SOC - Priority Queue",
                "High/Critical alarm_state buckets, ordered by risk score and represented raw volume.",
                PRIORITY_STATE,
                [
                    "timestamp",
                    "risk.level",
                    "risk.score",
                    "alarm.status",
                    "agent.id",
                    "agent.name",
                    "rule.id",
                    "rule.level",
                    "rule.description",
                    "source.raw_alert_count",
                    "source_observed.srcip_unique_count",
                    "source_observed.srcip_samples",
                    "asset.category",
                    "asset.owner",
                    "asset.environment",
                    "soc.recommended_action",
                    "soc.sla",
                ],
                [["risk.score", "desc"], ["source.raw_alert_count", "desc"]],
            ),
            build_search(
                "siem-alarm-soc-v1-search-escalations",
                "SIEM Alarm SOC - Escalation Feed",
                "Create-only risk-level events; timestamp is the source cause time and event.created is processing time.",
                ESCALATION,
                [
                    "event.created",
                    "timestamp",
                    "escalation.level",
                    "escalation.previous_level",
                    "escalation.reason",
                    "escalation.state_alarm_id",
                    "agent.id",
                    "agent.name",
                    "rule.id",
                    "rule.description",
                    "risk.score",
                    "source.raw_alert_count",
                    "source_observed.srcip_samples",
                    "soc.recommended_action",
                    "soc.sla",
                ],
                [["event.created", "desc"]],
            ),
            build_search(
                "siem-alarm-soc-v1-search-latest-escalated-alarms",
                "SIEM Alarm SOC - Latest Escalated Alarm Events",
                "Newest create-only SOC escalation events. Default columns are event time, rule description, risk level, and agent name.",
                ESCALATION,
                [
                    "event.created",
                    "rule.description",
                    "risk.level",
                    "agent.name",
                ],
                [["event.created", "desc"]],
            ),
            build_search(
                "siem-alarm-soc-v1-search-noisy",
                "SIEM Alarm SOC - Noisy States",
                "alarm_state buckets ordered by represented raw-alert count.",
                STATE,
                [
                    "timestamp",
                    "source.raw_alert_count",
                    "risk.level",
                    "risk.score",
                    "agent.id",
                    "agent.name",
                    "rule.id",
                    "rule.description",
                    "alarm.status",
                    "source_observed.srcip_samples",
                ],
                [["source.raw_alert_count", "desc"]],
            ),
            build_search(
                "siem-alarm-soc-v1-search-multi-ip",
                "SIEM Alarm SOC - Multi-source-IP States",
                "alarm_state buckets that retained more than one distinct source IP.",
                MULTI_IP_STATE,
                [
                    "timestamp",
                    "source_observed.srcip_unique_count",
                    "source_observed.srcip_samples",
                    "risk.level",
                    "risk.score",
                    "agent.id",
                    "agent.name",
                    "rule.id",
                    "rule.description",
                    "source.raw_alert_count",
                ],
                [["source_observed.srcip_unique_count", "desc"]],
            ),
        ]
    )

    overview_markdown = (
        "# SIEM Alarm - SOC Overview\n"
        "**Time picker applies to every data panel.** State panels count UTC hourly alarm buckets, "
        "not unresolved incidents. Escalation panels count create-only level events. "
        "`Raw alerts represented` is summed only from finalized state documents. "
        "Authoritative evidence remains in `wazuh-alerts-*`."
    )
    triage_markdown = (
        "# SIEM Alarm - SOC Triage & Investigation\n"
        "Start with **Priority Queue**, validate the Wazuh rule and retained entity samples, then pivot "
        "to the matching raw document in `wazuh-alerts-*`. `alarm.status` describes bucket lifecycle "
        "(`open`/`finalized`), not analyst case closure."
    )

    visualizations = [
        markdown_visualization("siem-alarm-soc-v1-viz-overview-header", "SIEM Alarm SOC - Overview Guidance", overview_markdown),
        markdown_visualization("siem-alarm-soc-v1-viz-triage-header", "SIEM Alarm SOC - Triage Guidance", triage_markdown),
        metric_visualization(
            "siem-alarm-soc-v1-viz-state-count",
            "Alarm state buckets",
            "Count of alarm_state documents; each document represents an agent/rule/hour bucket.",
            STATE,
            subtext="hourly state buckets",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-priority-count",
            "High + Critical buckets",
            "High or Critical alarm_state buckets in the selected time range.",
            PRIORITY_STATE,
            subtext="priority state buckets",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-critical-count",
            "Critical buckets",
            "Critical alarm_state buckets in the selected time range.",
            CRITICAL_STATE,
            subtext="critical state buckets",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-escalation-count",
            "Escalation events",
            "Count of alarm_escalation documents; one alarm can have multiple level events.",
            ESCALATION,
            subtext="create-only level events",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-raw-finalized",
            "Raw alerts represented",
            "Sum of source.raw_alert_count on finalized alarm_state documents only.",
            FINALIZED_STATE,
            agg_type="sum",
            field="source.raw_alert_count",
            subtext="finalized buckets only",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-affected-agents",
            "Affected agents",
            "Unique agent.id values represented by alarm_state buckets.",
            STATE,
            agg_type="cardinality",
            field="agent.id",
            subtext="unique agent IDs",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-asset-gaps",
            "Asset inventory gaps",
            "alarm_state buckets using the default asset value instead of explicit inventory metadata.",
            ASSET_GAP_STATE,
            subtext="desired value: 0",
        ),
        metric_visualization(
            "siem-alarm-soc-v1-viz-multi-ip-count",
            "Multi-source-IP buckets",
            "alarm_state buckets with more than one distinct retained source IP.",
            MULTI_IP_STATE,
            subtext="srcip_unique_count > 1",
        ),
        pie_filters_visualization(
            "siem-alarm-soc-v1-viz-risk-distribution",
            "Risk distribution - alarm states",
            "Fixed risk-level distribution over alarm_state buckets.",
            STATE,
            [(level, 'risk.level: "%s"' % level) for level in RISK_COLORS],
            RISK_COLORS,
        ),
        area_time_visualization(
            "siem-alarm-soc-v1-viz-state-trend",
            "Alarm-state trend by risk",
            "Hourly alarm_state bucket count split by current risk level.",
            STATE,
            split_field="risk.level",
            colors=RISK_COLORS,
        ),
        area_time_visualization(
            "siem-alarm-soc-v1-viz-raw-trend",
            "Represented raw-alert trend - finalized",
            "Sum of source.raw_alert_count over finalized alarm_state buckets.",
            FINALIZED_STATE,
            metric_type="sum",
            metric_field="source.raw_alert_count",
        ),
        area_time_visualization(
            "siem-alarm-soc-v1-viz-escalation-trend",
            "Escalation trend by level",
            "alarm_escalation event count split by escalation.level.",
            ESCALATION,
            split_field="escalation.level",
            split_size=3,
            colors={"Medium": RISK_COLORS["Medium"], "High": RISK_COLORS["High"], "Critical": RISK_COLORS["Critical"]},
        ),
        horizontal_terms_visualization(
            "siem-alarm-soc-v1-viz-top-agents",
            "Top agents by represented raw alerts",
            "Sum of source.raw_alert_count by agent.id over alarm_state documents.",
            STATE,
            "agent.id",
            metric_type="sum",
            metric_field="source.raw_alert_count",
            size=10,
        ),
        horizontal_terms_visualization(
            "siem-alarm-soc-v1-viz-top-rules",
            "Top Wazuh rules by represented raw alerts",
            "Sum of source.raw_alert_count by rule.description.keyword over alarm_state documents.",
            STATE,
            "rule.description.keyword",
            metric_type="sum",
            metric_field="source.raw_alert_count",
            size=10,
        ),
        horizontal_terms_visualization(
            "siem-alarm-soc-v1-viz-source-ip-presence",
            "Source-IP presence across alarm states",
            "State-document presence by retained source IP sample; this is not exact raw-event IP frequency.",
            STATE,
            "source_observed.srcip_samples",
            size=15,
        ),
        pie_terms_visualization(
            "siem-alarm-soc-v1-viz-asset-source",
            "Asset metadata source coverage",
            "alarm_state distribution by asset.source.",
            STATE,
            "asset.source",
            size=3,
            colors={"assets_json": "#2F9D98", "agent_label": "#6092C0", "default": "#BD271E"},
        ),
        pie_terms_visualization(
            "siem-alarm-soc-v1-viz-escalation-reason",
            "Escalation reasons",
            "alarm_escalation distribution by initial eligible level versus risk increase.",
            ESCALATION,
            "escalation.reason",
            size=2,
            colors={"initial_eligible_level": "#6092C0", "risk_level_increased": "#BD271E"},
        ),
    ]
    records.extend(visualizations)

    overview_panels = [
        panel(1, "visualization", "siem-alarm-soc-v1-viz-overview-header", 0, 0, 48, 5),
        panel(2, "visualization", "siem-alarm-soc-v1-viz-state-count", 0, 5, 8, 8),
        panel(3, "visualization", "siem-alarm-soc-v1-viz-priority-count", 8, 5, 8, 8),
        panel(4, "visualization", "siem-alarm-soc-v1-viz-critical-count", 16, 5, 8, 8),
        panel(5, "visualization", "siem-alarm-soc-v1-viz-escalation-count", 24, 5, 8, 8),
        panel(6, "visualization", "siem-alarm-soc-v1-viz-raw-finalized", 32, 5, 8, 8),
        panel(7, "visualization", "siem-alarm-soc-v1-viz-affected-agents", 40, 5, 8, 8),
        panel(8, "search", "siem-alarm-soc-v1-search-latest-escalated-alarms", 0, 13, 48, 16),
        panel(9, "visualization", "siem-alarm-soc-v1-viz-state-trend", 0, 29, 32, 16),
        panel(10, "visualization", "siem-alarm-soc-v1-viz-risk-distribution", 32, 29, 16, 16),
        panel(11, "visualization", "siem-alarm-soc-v1-viz-raw-trend", 0, 45, 24, 16),
        panel(12, "visualization", "siem-alarm-soc-v1-viz-escalation-trend", 24, 45, 24, 16),
        panel(13, "visualization", "siem-alarm-soc-v1-viz-top-agents", 0, 61, 16, 16),
        panel(14, "visualization", "siem-alarm-soc-v1-viz-top-rules", 16, 61, 32, 16),
        panel(15, "visualization", "siem-alarm-soc-v1-viz-source-ip-presence", 0, 77, 24, 16),
        panel(16, "visualization", "siem-alarm-soc-v1-viz-asset-source", 24, 77, 12, 16),
        panel(17, "visualization", "siem-alarm-soc-v1-viz-escalation-reason", 36, 77, 12, 16),
    ]
    triage_panels = [
        panel(1, "visualization", "siem-alarm-soc-v1-viz-triage-header", 0, 0, 48, 5),
        panel(2, "visualization", "siem-alarm-soc-v1-viz-priority-count", 0, 5, 16, 8),
        panel(3, "visualization", "siem-alarm-soc-v1-viz-asset-gaps", 16, 5, 16, 8),
        panel(4, "visualization", "siem-alarm-soc-v1-viz-multi-ip-count", 32, 5, 16, 8),
        panel(5, "search", "siem-alarm-soc-v1-search-priority", 0, 13, 48, 20),
        panel(6, "search", "siem-alarm-soc-v1-search-escalations", 0, 33, 48, 18),
        panel(7, "search", "siem-alarm-soc-v1-search-noisy", 0, 51, 48, 18),
        panel(8, "search", "siem-alarm-soc-v1-search-multi-ip", 0, 69, 48, 18),
    ]
    records.extend(
        [
            build_dashboard(
                "siem-alarm-soc-v1-dashboard-overview",
                "SIEM Alarm SOC - Overview",
                "Operational SOC overview for aggregated alarm_state and alarm_escalation documents.",
                overview_panels,
            ),
            build_dashboard(
                "siem-alarm-soc-v1-dashboard-triage",
                "SIEM Alarm SOC - Triage & Investigation",
                "Priority, escalation, noisy-state, and multi-source-IP investigation queues.",
                triage_panels,
            ),
        ]
    )
    return records


def validate_records(records, template):
    allowed_types = {"index-pattern", "search", "visualization", "dashboard"}
    keys = [(record["type"], record["id"]) for record in records]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate (type, id) in bundle")
    if any(record["type"] not in allowed_types for record in records):
        raise ValueError("unexpected Saved Object type")

    object_keys = set(keys)
    for record in records:
        for reference in record.get("references", []):
            referenced_key = (reference["type"], reference["id"])
            if referenced_key not in object_keys:
                raise ValueError("missing reference %r from %r" % (referenced_key, keys))

    data_views = [record for record in records if record["type"] == "index-pattern"]
    if len(data_views) != 1:
        raise ValueError("bundle must contain exactly one data view")
    attributes = data_views[0]["attributes"]
    if attributes.get("title") != DATA_VIEW_TITLE or attributes.get("timeFieldName") != TIME_FIELD:
        raise ValueError("data view title/time field mismatch")

    mapping_fields = dict(
        flatten_mapping_fields(template["template"]["mappings"]["properties"])
    )
    for record in records:
        if record["type"] == "visualization":
            vis_state = json.loads(record["attributes"]["visState"])
            search_json = json.loads(record["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            if vis_state["type"] != "markdown":
                query = search_json.get("query", {}).get("query", "")
                if "document.type" not in query:
                    raise ValueError("data visualization lacks document.type filter: " + record["id"])
                if search_json.get("indexRefName") != "kibanaSavedObjectMeta.searchSourceJSON.index":
                    raise ValueError("visualization lacks indexRefName: " + record["id"])
                for agg in vis_state.get("aggs", []):
                    field = agg.get("params", {}).get("field")
                    if field and field not in mapping_fields:
                        raise ValueError("unknown aggregation field %s in %s" % (field, record["id"]))
                    if field and mapping_fields[field] == "text":
                        raise ValueError("text field used for aggregation: " + field)
                    if (
                        agg.get("type") == "sum"
                        and field == "source.raw_alert_count"
                        and 'document.type: "alarm_escalation"' in query
                    ):
                        raise ValueError("raw-alert volume must not be summed on escalation documents")
        elif record["type"] == "search":
            search_json = json.loads(record["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            if "document.type" not in search_json.get("query", {}).get("query", ""):
                raise ValueError("saved search lacks document.type filter: " + record["id"])
        elif record["type"] == "dashboard":
            panels = json.loads(record["attributes"]["panelsJSON"])
            references = {ref["name"]: ref for ref in record["references"]}
            if len(panels) != len(references):
                raise ValueError("dashboard panel/reference count mismatch: " + record["id"])
            for dashboard_panel in panels:
                if dashboard_panel["panelRefName"] not in references:
                    raise ValueError("unresolved dashboard panelRefName")

    serialized = "\n".join(compact(record) for record in records)
    forbidden = ("password", "api_key", "authorization: basic", "http://", "https://")
    lowered = serialized.lower()
    for token in forbidden:
        if token in lowered:
            raise ValueError("forbidden secret/external URL token in artifact: " + token)


def render_ndjson(records):
    return "\n".join(compact(record) for record in records) + "\n"


def render_manifest(records, ndjson_text):
    counts = Counter(record["type"] for record in records)
    dashboards = [
        {"id": record["id"], "title": record["attributes"]["title"]}
        for record in records
        if record["type"] == "dashboard"
    ]
    manifest = {
        "artifact": OUTPUT_PATH.name,
        "artifact_sha256": hashlib.sha256(ndjson_text.encode("utf-8")).hexdigest(),
        "bundle_version": BUNDLE_VERSION,
        "compatibility": {
            "wazuh_dashboard": "4.14.7",
            "opensearch_dashboards": "2.19.5",
            "saved_object_schema": "legacy aggregation-based visualizations",
        },
        "data_view": {"id": DATA_VIEW_ID, "title": DATA_VIEW_TITLE, "time_field": TIME_FIELD},
        "dashboards": dashboards,
        "object_count": len(records),
        "object_ids": [{"type": record["type"], "id": record["id"]} for record in records],
        "target_tenant": "operator-selected custom SOC tenant",
        "type_counts": dict(sorted(counts.items())),
    }
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_export_request(records):
    """Build an exact-ID request for a controlled pre-upgrade backup export."""
    request = {
        "objects": [{"type": record["type"], "id": record["id"]} for record in records],
        "includeReferencesDeep": False,
        "excludeExportDetails": False,
    }
    return json.dumps(request, ensure_ascii=False, indent=2) + "\n"


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate that committed artifacts exactly match the deterministic build",
    )
    args = parser.parse_args(argv)

    with TEMPLATE_PATH.open("r", encoding="utf-8") as handle:
        template = json.load(handle)
    records = build_records(template)
    validate_records(records, template)
    ndjson_text = render_ndjson(records)
    manifest_text = render_manifest(records, ndjson_text)
    export_request_text = render_export_request(records)

    if args.check:
        failures = []
        for path, expected in (
            (OUTPUT_PATH, ndjson_text),
            (MANIFEST_PATH, manifest_text),
            (EXPORT_REQUEST_PATH, export_request_text),
        ):
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                failures.append(str(path))
        if failures:
            print("[-] Generated artifact differs: %s" % ", ".join(failures), file=sys.stderr)
            return 1
        print("[+] SOC dashboard bundle valid and reproducible: %d objects" % len(records))
        print("[+] SHA256: %s" % hashlib.sha256(ndjson_text.encode("utf-8")).hexdigest())
        return 0

    write_text(OUTPUT_PATH, ndjson_text)
    write_text(MANIFEST_PATH, manifest_text)
    write_text(EXPORT_REQUEST_PATH, export_request_text)
    print("[+] Wrote %s (%d objects)" % (OUTPUT_PATH, len(records)))
    print("[+] Wrote %s" % MANIFEST_PATH)
    print("[+] Wrote %s" % EXPORT_REQUEST_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
