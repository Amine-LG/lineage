"""Images page bucket counts."""

from lineage.main import app
from .conftest import make_index


def _ns(name, requester=None):
    annotations = {"openshift.io/requester": requester} if requester else {}
    return {"name": name, "labels": {}, "annotations": annotations}


def _imagestream(name, namespace):
    return {
        "name": name,
        "namespace": namespace,
        "dockerImageRepository": (
            f"image-registry.openshift-image-registry.svc:5000/"
            f"{namespace}/{name}"
        ),
        "spec_tags": [],
        "status_tags": [],
    }


def test_images_bucket_counts_include_imagestreams(monkeypatch):
    idx = make_index(
        namespaces=[
            _ns("openshift"),
            _ns("project-a", requester="alice"),
            _ns("raw-a"),
        ],
        imagestreams=[
            _imagestream("platform", "openshift"),
            _imagestream("app", "project-a"),
            _imagestream("raw", "raw-a"),
        ],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/images?bucket=unknown#images-overview").get_data(
            as_text=True)

    assert 'Unclassified <span class="dim mono">1</span>' in body
    assert 'Yours <span class="dim mono">1</span>' in body
    assert 'Baseline <span class="dim mono">1</span>' in body
    assert 'All <span class="dim mono">3</span>' in body
    assert "Images (0 of 0)" in body
    assert "ImageStreams (1 of 3)" in body
    assert "raw-a" in body
