class StubRepository:
    def __init__(self):
        self.values = {
            "congestion_threshold_percent": 70,
            "automatic_response_enabled": True,
            "updated_at": None,
        }

    def get(self):
        return dict(self.values)

    def update(self, **values):
        self.values.update(values)
        return dict(self.values)


def test_platform_settings_service_reads_and_updates_runtime_values(
    load_service_module,
):
    module = load_service_module(
        "platform_settings_service",
        stubs={
            "app.core.config": {
                "settings": type(
                    "Settings",
                    (),
                    {"controller_base_url": "http://controller:8080"},
                )(),
            },
            "app.repositories.platform_settings_repository": {
                "PlatformSettingsRepository": StubRepository,
            },
        },
    )
    repository = StubRepository()
    service = module.PlatformSettingsService(repository)

    assert service.get()["controller_base_url"] == "http://controller:8080"
    updated = service.update({
        "congestion_threshold_percent": 82,
        "automatic_response_enabled": False,
    })

    assert updated["congestion_threshold_percent"] == 82
    assert updated["automatic_response_enabled"] is False
