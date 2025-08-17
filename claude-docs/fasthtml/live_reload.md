# Live Reloading

Source: [https://www.fastht.ml/docs/ref/live_reload.html](https://www.fastht.ml/docs/ref/live_reload.html)

---

1. [Reference](https://www.fastht.ml/docs/ref/../ref/concise_guide.html)
2. [Live Reloading](https://www.fastht.ml/docs/ref/../ref/live_reload.html)

# Live Reloading

When building your app it can be useful to view your changes in a web browser as you make them. FastHTML supports live reloading which means that it watches for any changes to your code and automatically refreshes the webpage in your browser.

To enable live reloading simply replace [FastHTML](https://www.fastht.ml/docs/api/core.html#fasthtml) in your app with `FastHTMLWithLiveReload`.

```python
from fasthtml.common import *
app = FastHTMLWithLiveReload()
```

Then in your terminal run `uvicorn` with reloading enabled.

```
uvicorn main:app --reload
```

**⚠️ Gotchas** - A reload is only triggered when you save your changes. - `FastHTMLWithLiveReload` should only be used during development. - If your app spans multiple directories you might need to use the `--reload-dir` flag to watch all files in each directory. See the uvicorn [docs](https://www.uvicorn.org/settings/#development) for more info. - The live reload script is only injected into the page when rendering [ft components](https://www.fastht.ml/docs/explains/explaining_xt_components.html).

## Live reloading withfast_app

In development the `fast_app` function provides the same functionality. It instantiates the `FastHTMLWithLiveReload` class if you pass `live=True`:

```
main.py
```

```python
from fasthtml.common import *

app, rt = fast_app(live=True)

serve()
```

To run `main.py` in live reload mode, just do `python main.py`. We recommend turning off live reload when deploying your app to production.