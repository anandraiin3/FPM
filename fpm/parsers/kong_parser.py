"""
Kong Gateway YAML parser — extracts services, routes, and plugins.
"""
from pathlib import Path

import yaml


def parse_kong(file_path: str) -> list[dict]:
    """
    Parse a Kong declarative YAML file and return structured control records.

    Produces one record per plugin (with its parent service and route context),
    plus one record per service/route mapping.
    """
    text = Path(file_path).read_text()
    data = yaml.safe_load(text)
    controls: list[dict] = []

    for svc in data.get("services", []):
        svc_name = svc.get("name", "unknown")
        svc_url = svc.get("url", "")

        routes = svc.get("routes", [])
        route_info = []
        for route in routes:
            route_info.append({
                "name": route.get("name", ""),
                "paths": route.get("paths", []),
                "methods": route.get("methods", []),
            })

        # Record the service→route mapping
        controls.append({
            "control_id": f"kong-svc:{svc_name}",
            "control_type": "service_route",
            "layer": "Gateway",
            "source_file": file_path,
            "raw_block": yaml.dump({"service": svc_name, "url": svc_url, "routes": route_info}, default_flow_style=False),
            "metadata": {
                "service_name": svc_name,
                "service_url": svc_url,
                "routes": route_info,
            },
        })

        # Record each plugin
        plugins = svc.get("plugins", [])
        for plugin in plugins:
            plugin_name = plugin.get("name", "unknown")
            plugin_config = plugin.get("config", {})
            plugin_enabled = plugin.get("enabled", True)

            # Build a readable block
            plugin_block = yaml.dump({
                "service": svc_name,
                "routes": [r.get("paths", []) for r in routes],
                "plugin": plugin_name,
                "enabled": plugin_enabled,
                "config": plugin_config,
            }, default_flow_style=False)

            controls.append({
                "control_id": f"kong-plugin:{svc_name}:{plugin_name}",
                "control_type": "gateway_plugin",
                "layer": "Gateway",
                "source_file": file_path,
                "raw_block": plugin_block,
                "metadata": {
                    "service_name": svc_name,
                    "service_url": svc_url,
                    "routes": route_info,
                    "plugin_name": plugin_name,
                    "plugin_config": plugin_config,
                    "plugin_enabled": plugin_enabled,
                },
            })

        # If no plugins, note the absence (important for true-positive detection)
        if not plugins:
            controls.append({
                "control_id": f"kong-no-plugins:{svc_name}",
                "control_type": "no_plugins",
                "layer": "Gateway",
                "source_file": file_path,
                "raw_block": f"Service {svc_name} ({svc_url}) has NO plugins configured on routes: {route_info}",
                "metadata": {
                    "service_name": svc_name,
                    "service_url": svc_url,
                    "routes": route_info,
                    "warning": "No authentication, rate-limiting, or validation plugins applied",
                },
            })

    return controls
