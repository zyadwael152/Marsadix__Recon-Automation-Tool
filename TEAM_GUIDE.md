# دليل الفريق خطوة بخطوة: نزّل Marsadix واربط كودك بيه

> الدليل مقسوم لجزئين: **الجزء أ** (خطوات 1 إلى 9) بيجهّز التول على جهازك، و**الجزء ب** (خطوات 10 إلى 18) بيوريك إزاي تربط الكود بتاعك بيها.
> كل خطوة فيها: **اعمل إيه**، و**إزاي تتأكد إنها نجحت**، و**لو فشلت**. خلّص الخطوة وتأكد منها قبل ما تروح للي بعدها.
> كل الأوامر مكتوبة لـ **Windows (PowerShell)** و**Linux**، وبتشتغل في الاتنين.

---

# الجزء أ: شغّل التول عندك

## خطوة 1 — ثبّت المتطلبات

محتاج: **Python 3.10 أو أحدث**، و**Git**، و**Docker** (للخطوة 8).

**Windows:** نزّل Python من `python.org` (وعلّم على **Add python.exe to PATH** وقت التثبيت)، وGit من `git-scm.com`، وDocker Desktop.

**Linux (Ubuntu / Debian / Kali):**

```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl unzip
```

**اتأكد:**

```
python --version        # on Linux: python3 --version
git --version
```

المفروض Python يطلع `3.10` أو أعلى. لو أقل، حدّث Python قبل ما تكمّل.

## خطوة 2 — نزّل المشروع

```
git clone <repo-url>
cd Marsadix
```

الـ `<repo-url>` هتاخده من صاحب الـ Repo.

## خطوة 3 — اعمل بيئة Python معزولة (venv)

**Windows (PowerShell):**

```
python -m venv .venv
.venv\Scripts\Activate.ps1
```

لو ظهرت رسالة إن تشغيل السكريبتات ممنوع، شغّل السطر ده مرة واحدة وكرر الأمر:

```
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Linux:**

```
python3 -m venv .venv
source .venv/bin/activate
```

**اتأكد:** أول سطر الترمنال بقى يبدأ بـ `(.venv)`.

> لازم تفعّل الـ venv (سطر `Activate`) في **كل ترمنال جديد** قبل ما تشتغل.

## خطوة 4 — ثبّت المشروع

```
pip install -e .
pip install pytest
```

كلمة `-e` معناها إن أي تعديل في الكود بيظهر على طول من غير إعادة تثبيت.

**اتأكد:**

```
marsadix doctor
```

المفروض يظهر الـ banner (اسم Marsadix بحروف كبيرة) وقايمة الأدوات. في الوقت ده أغلبها هيبقى `MISSING`، وده طبيعي لأننا لسه ما ثبتناهم.

**لو فشلت:** `marsadix: command not found` معناها إن الـ venv مش مفعّل (خطوة 3)، أو `pip install -e .` ما اتعملش.

## خطوة 5 — ثبّت الأدوات الخارجية

التول بتشغّل أدوات جاهزة من برّه. لازم تتثبت وتبقى في الـ **PATH**:

| الأداة | بتعمل إيه | بتتستخدم في |
| --- | --- | --- |
| subfinder | اكتشاف subdomains (passive) | Recon |
| dnsx | التأكد إن الـ host بيتحل (DNS) | Recon |
| httpx (ProjectDiscovery) | هل الـ host شغال؟ تقنياته؟ | Recon |
| naabu | فحص البورتات | Recon |
| nmap | تعريف الخدمات وإصداراتها | Recon |
| katana | crawl للمواقع وجمع URLs | Web Surface |
| gau | URLs أرشيفية | Web Surface |
| nuclei | فحوصات آمنة (takeover وexposures) | ASM |
| ffuf | fuzzing (اختياري) | Active checks |

**Windows (PowerShell):**

```
powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1 -AddToPath
winget install Insecure.Nmap
```

السكريبت بينزّل الأدوات في `%USERPROFILE%\marsadix-tools\bin` (ولو عايز مكان تاني: `-InstallDir D:\tools\bin`)، وبيضيفه للـ PATH. بعدها **اقفل الترمنال وافتح واحد جديد** (وفعّل الـ venv تاني).

**Linux:**

```
bash scripts/install-tools.sh
sudo apt install -y nmap libpcap-dev
```

السكريبت بينزّل الأدوات في `~/.local/bin`. لو الفولدر ده مش في الـ PATH، السكريبت هيطبعلك السطر اللي تنسخه في `~/.bashrc`، وبعدين:

```
source ~/.bashrc
```

> **ملاحظة على Kali:** باكدج `httpx` في apt بيتسمّى `httpx-toolkit`، وأمره **مش** `httpx`، فالتول مش هتلاقيه. استخدم السكريبت (بينزّل أداة ProjectDiscovery باسم `httpx`).

**اتأكد:**

```
marsadix doctor
```

المفروض يظهر في آخره `9/9 tools found`.

**لو فشلت:**

| الرسالة | الحل |
| --- | --- |
| `MISSING` لأداة | مش في الـ PATH. افتح ترمنال جديد وفعّل الـ venv، وتأكد من فولدر التثبيت |
| تحذير إن `httpx` مش بتاع ProjectDiscovery | فيه حزمة Python اسمها `httpx` بتثبّت أمر بنفس الاسم. حط فولدر أدوات ProjectDiscovery **قبله** في الـ PATH |
| `FAILED` أثناء التحميل | افحص الإنترنت وجرّب تاني. لو في Windows وفضل فاشل، ممكن Windows Defender مسح الملف (Windows Security ثم Virus & threat protection ثم Exclusions) |
| naabu طلب Npcap (Windows) أو libpcap (Linux) | ثبّته (`npcap.com` أو `sudo apt install libpcap-dev`) |

## خطوة 6 — جهّز الأسرار (`.env`)

**Windows:**

```
Copy-Item .env.example .env
notepad .env
```

**Linux:**

```
cp .env.example .env
nano .env
```

املا القيم:

- `NVD_API_KEY=` مفتاح **مجاني**: ادخل `nvd.nist.gov/developers/request-an-api-key` وحط إيميلك، والمفتاح بيوصلك على الإيميل. من غيره NVD بيحدّد عدد الطلبات.
- `DISCORD_WEBHOOK_URL=` اختياري. لو عايز تنبيهات: في سيرفر Discord بتاعك افتح Settings ثم Integrations ثم Webhooks ثم New Webhook، وانسخ الرابط.

**اتأكد:** شغّل `marsadix doctor` وبص على آخر سطر. المفروض يقول `API key: set`.

> **مهم جداً:** ملف `.env` **ما بيترفعش على GitHub أبداً**. بعد ما تعمله، شغّل `git status` وتأكد إنه **مش ظاهر** في القايمة.

## خطوة 7 — شغّل الاختبارات

```
python -m pytest -q
```

المفروض كل الاختبارات تنجح (`passed` ومفيش `failed`). لو في اختبار فشل من أول يوم، بلّغ الفريق قبل ما تكتب أي كود.

## خطوة 8 — هدف تجربة آمن

التول بتفحص مواقع، فالتجارب تبقى **على أهداف مصرّح بيها بس**. الهدف الأسهل هو Juice Shop على جهازك:

```
docker run -d -p 3000:3000 bkimminich/juice-shop
```

**اتأكد:** افتح `http://localhost:3000` في المتصفح. لما تخلّص: `docker ps` تشوف الـ ID، وبعدين `docker stop <id>`.

كمان فيه دومين عام اتعمل أصلاً للاختبار، وهو `vulnweb.com` (بتاع Acunetix)، ونستخدمه في أمثلة الدليل.

## خطوة 9 — جرّب فلتر الـ Scope

الـ **Scope** هو القايمة اللي بتحدد إيه المسموح تفحصه. اعمل ملف `scope.txt`:

**Windows:**

```
Set-Content scope.txt "*.vulnweb.com","vulnweb.com","!rest.vulnweb.com"
```

**Linux:**

```
printf '*.vulnweb.com\nvulnweb.com\n!rest.vulnweb.com\n' > scope.txt
```

وجرّب:

```
marsadix scope scope.txt www.vulnweb.com rest.vulnweb.com google.com vulnweb.com
```

**المفروض يطلع:**

```
  IN   www.vulnweb.com       matches *.vulnweb.com
  OUT  rest.vulnweb.com      excluded by !rest.vulnweb.com
  OUT  google.com            no matching rule
  IN   vulnweb.com           matches vulnweb.com
```

الفكرة: `*.` معناها أي subdomain، و`!` معناها استثناء، والاستثناء دايماً بيكسب، وأي حاجة مش مطابقة لقاعدة تبقى `OUT`.

**كده جهازك جاهز.** الجزء ب بيشرح إزاي تربط كودك.

---

# الجزء ب: اربط كودك بالتول

## خطوة 10 — افهم إزاي التول بتشغّل كودك

لما حد يكتب `marsadix scan vulnweb.com`، التول بتعمل ده بالترتيب:

1. تتأكد إن الهدف داخل الـ Scope.
2. تسجّل **Scan** جديد في قاعدة البيانات.
3. تعدّي على **المراحل (Stages)** واحدة واحدة، وتشغّل كل مرحلة لو لقت الملف بتاعها.
4. لو المرحلة **مالقتهاش** تتخطاها (`skipped`). لو المرحلة **اتكسرت** بخطأ تسجّلها `failed` وتكمّل الباقي.

يعني **ماتحتاجش تعدّل أي ملف من النواة**: بتحط ملفك في مكانه المتفق عليه، وبتكتب دالة باسم معين، والتول بتلاقيها وتشغّلها لوحدها.

**المراحل الحالية (أمر `scan`):**

| المرحلة | الملف | الدالة |
| --- | --- | --- |
| recon | `marsadix/recon/stage.py` | `run(ctx)` |
| web | `marsadix/web/stage.py` | `run(ctx)` |
| asm | `marsadix/asm/stage.py` | `run(ctx)` |
| track | `marsadix/core/diff.py` | `run_stage(ctx)` |

**الأوامر التانية:**

| الأمر | الملف | الدالة |
| --- | --- | --- |
| `marsadix monitor` | `marsadix/monitor/runner.py` | `run(conn, config, dry_run=False, since=None)` |
| `marsadix diff` | `marsadix/core/diff.py` | `run_diff(conn, target, old_id=None, new_id=None)` |
| `marsadix report` | `marsadix/reports/generate.py` | `generate_report(conn, target, fmt, out_dir, scan_id=None)` |

**الـ `ctx` اللي بتستقبله المرحلة:**

| الحقل | معناه |
| --- | --- |
| `ctx.target` | الدومين المستهدف (مثلاً `vulnweb.com`) |
| `ctx.in_scope(host)` | هل الـ host مسموح (`True` أو `False`) |
| `ctx.scan` | كائن الـ Scan الحالي (`ctx.scan.id` وغيره) |
| `ctx.conn` | اتصال قاعدة البيانات |
| `ctx.config` | الإعدادات |

## خطوة 11 — حدد ملفك

دور على اسمك في الجدول، وده الملف اللي هتكتبه:

| الشخص | الدور | ملفك |
| --- | --- | --- |
| 1 | Recon | `marsadix/recon/stage.py` |
| 2 | Web Surface + ASM | `marsadix/web/stage.py` و`marsadix/asm/stage.py` |
| 3 و4 | CVE Monitor | `marsadix/monitor/runner.py` |
| 5 | Core + Reports | `marsadix/core/diff.py` و`marsadix/reports/generate.py` |

## خطوة 12 — اعمل Branch خاص بيك

متشتغلش على `main` مباشرة:

```
git checkout -b feature/اسم-شغلك
```

استخدم اسم إنجليزي بدون مسافات، مثلاً `feature/recon-stage`.

**اتأكد:** `git branch` بيظهر اسم الـ Branch الجديد بنجمة جنبه.

## خطوة 13 — اكتب أول كود: مرحلة "Hello"

الهدف إنك تتأكد إن التول **بتلاقي ملفك وبتشغّله**، قبل ما تكتب المنطق الحقيقي. هنعمل مثال لـ Recon، وإنت غيّر الأسماء حسب ملفك من خطوة 11.

**اعمل الفولدر والملفات:**

Windows:

```
mkdir marsadix\recon
New-Item marsadix\recon\__init__.py -ItemType File
notepad marsadix\recon\stage.py
```

Linux:

```
mkdir -p marsadix/recon
touch marsadix/recon/__init__.py
nano marsadix/recon/stage.py
```

> لو الفولدر موجود أصلاً، متعملوش تاني. وكل فولدر جديد لازم يكون فيه ملف `__init__.py` (فاضي).

**اكتب جوه `stage.py`:**

```python
import logging

log = logging.getLogger(__name__)


def run(ctx):
    log.info("hello from the recon stage, target=%s", ctx.target)
    log.info("is the target in scope? %s", ctx.in_scope(ctx.target))
```

**شغّل:**

```
marsadix -v scan vulnweb.com
```

> الـ `-v` لازم يجي **قبل** كلمة `scan` (ده خيار عام).

**المفروض يطلع (مع بعض التفاصيل الزيادة):**

```
WARNING marsadix.cli: no --scope given: using vulnweb.com and *.vulnweb.com
INFO marsadix.core.pipeline: scan #1 started: vulnweb.com (baseline=True)
INFO marsadix.core.pipeline: stage 'recon' started
INFO marsadix.recon.stage: hello from the recon stage, target=vulnweb.com
INFO marsadix.recon.stage: is the target in scope? True
INFO marsadix.core.pipeline: stage 'web' not implemented yet, skipping
...
Scan #1 of vulnweb.com: completed (baseline)
  recon    ok
  web      skipped  marsadix.web.stage:run not found
  asm      skipped  marsadix.asm.stage:run not found
  track    skipped  marsadix.core.diff:run_stage not found
```

**معنى النتيجة:**

- `recon ok` معناها التول لقت ملفك وشغّلته.
- `skipped ... not found` للمراحل اللي لسه محدش كتبها، وده طبيعي.

**لو ظهر `recon skipped`:** اسم الملف أو الدالة أو الفولدر غلط (حتى حرف واحد)، أو ناقص `__init__.py`. قارن بجدول خطوة 10.
**لو ظهر `recon failed`:** الكود اتكسر. الخطأ الكامل بيظهر في اللوج فوق.

التشغيل ده بيعمل ملف `marsadix.db` في فولدر المشروع، وده طبيعي ومش بيترفع على Git.

## خطوة 14 — استبدل الـ Hello بكودك الحقيقي

لما الـ Hello يشتغل، ابدأ اكتب المنطق الحقيقي. القواعد:

**1) افصل شغلك لجزئين:**

- **Wrapper** (دالة بسيطة): بتشغّل الأداة وبترجّع نتيجة. مفيهاش قاعدة بيانات.
- **Stage** (`run(ctx)`): بتنادي الـ wrapper وبتفلتر بالـ Scope وبتخزّن.

الفصل ده بيخليك تختبر الـ wrapper من غير ما تشغّل الأداة فعلاً.

**2) شغّل الأدوات الخارجية عن طريق `core/runner.py` مش `subprocess` مباشرة.** ده بيضمن timeout وإنه مش بيستخدم shell:

```python
# marsadix/recon/mytool.py  (a wrapper)
from ..core.runner import run_tool, parse_json_lines


def run_mytool(domain, timeout=300):
    res = run_tool(["mytool", "-d", domain, "-silent"], timeout=timeout)
    return parse_json_lines(res.stdout)
```

- لو الأداة مش متثبتة، `run_tool` بترفع `ToolNotFound`.
- لو الأداة اتأخرت، النتيجة فيها `res.timed_out` والكود **ما بيقفش**.
- `parse_json_lines` بتحوّل مخرجات الأدوات اللي بتطبع JSON في كل سطر (زي httpx وnuclei وkatana).

**3) افحص الـ Scope قبل أي فحص نشط:**

```python
for host in hosts:
    if not ctx.in_scope(host):
        continue
    # ... only now touch the host
```

وده بينطبق على أي host جديد بتلاقيه (حتى لو جه من ملف JavaScript).

**4) الأسرار والإعدادات** من `ctx.config` والـ `.env`، **مش** مكتوبة في الكود.

## خطوة 15 — خزّن النتايج (models وقاعدة البيانات)

التول بتتبادل البيانات بين المراحل عن طريق **كائنات** معرّفة في `marsadix/models.py`، وبتتحفظ بدوال `marsadix/db.py`. **ماتكتبش SQL بإيدك.**

| الموديول | بيكتب |
| --- | --- |
| Recon | `Asset` و`Service` و`Technology` و`WebItem` و`Email` |
| ASM (Nuclei) | `Finding` بـ `source=nuclei` |
| CVE Monitor | `CVE` و`Finding` بـ `source=cve_match` و`Alert` |
| Core | `TrackedAsset` و`ScanDiff` |

**مثال:** حفظ assets جوه الـ stage:

```python
from .. import db
from ..models import Asset, DiscoverySource


def run(ctx):
    hosts = ["dev.vulnweb.com", "www.vulnweb.com"]          # your real results here
    assets = [Asset(scan_id=ctx.scan.id, host=h, source=DiscoverySource.PASSIVE)
              for h in hosts if ctx.in_scope(h)]
    db.save_many(ctx.conn, "assets", assets)
```

- التكرار بيتتجاهل لوحده، فمفيش مشكلة لو حفظت نفس الحاجة مرتين.
- الـ hosts بتتوحّد تلقائياً (حروف صغيرة وبدون نقطة في الآخر).
- دوال القراءة: `get_assets` و`get_services` و`get_technologies` و`get_web_items` و`get_findings` و`get_cves` و`get_pending_alerts` و`get_latest_scans`.

**لو غيّرت في `models.py` أو الجداول:** كلّم الفريق الأول، وارفع `SCHEMA_VERSION` في `db.py`، وامسح ملف `marsadix.db` المحلي.

## خطوة 16 — اكتب اختبار

حط اختبارك في `tests/test_<اسم>.py`. اتنين أمثلة:

```python
from types import SimpleNamespace

from marsadix.core.runner import ToolResult
from marsadix.recon import mytool
from marsadix.recon.stage import run


def test_stage_runs_without_crashing():
    ctx = SimpleNamespace(target="example.com", in_scope=lambda host: True)
    run(ctx)


def test_wrapper_parses_output(monkeypatch):
    fake = ToolResult(cmd=["mytool"], returncode=0,
                      stdout='{"host":"a.example.com"}\n', stderr="", duration=0.1)
    monkeypatch.setattr(mytool, "run_tool", lambda cmd, **kw: fake)
    assert mytool.run_mytool("example.com") == [{"host": "a.example.com"}]
```

الفكرة في التاني: بنستبدل `run_tool` بنتيجة مزيفة، فالاختبار **ما بيشغّلش الأداة الحقيقية** وبيشتغل على أي جهاز.

**شغّل:**

```
python -m pytest -q
```

**نصايح:** ما تعتمدش على الإنترنت في الاختبارات، وما تشغّلش أدوات حقيقية فيها، وحفظ عينة مخرجات حقيقية في `tests/fixtures/` وجرّب عليها.

## خطوة 17 — سلّم شغلك (Commit وPull Request)

**قبل أي commit، اتأكد:**

```
git status
```

مفيش في القايمة: `.env` ولا `*.db` ولا مجلدات النتايج. لو ظهروا، **ماتضيفهمش**.

**ثم:**

```
git add marsadix tests
git commit -m "recon: add stage and subfinder wrapper"
git push -u origin feature/اسم-شغلك
```

بعدين افتح **Pull Request** على GitHub من الـ Branch بتاعك على `main`، وصاحب الـ Core هيراجع ويعمل Merge.

**Checklist قبل الـ Pull Request:**

- [ ] `python -m pytest -q` بينجح كله
- [ ] `marsadix scan vulnweb.com` (أو الأمر بتاعك) بيشتغل ومرحلتك `ok`
- [ ] مفيش أسرار ولا ملفات `.env` أو `*.db` في الـ commit
- [ ] فحصت `ctx.in_scope(host)` قبل أي فحص نشط
- [ ] أضفت اختبار واحد على الأقل

## خطوة 18 — لو حاجة وقفت

| المشكلة | السبب والحل |
| --- | --- |
| `marsadix: command not found` | الـ venv مش مفعّل (خطوة 3)، أو `pip install -e .` ما اتعملش |
| `ModuleNotFoundError: marsadix` | نفس السبب: الـ venv غلط أو التثبيت ناقص |
| مرحلتك `skipped ... not found` | اسم الملف أو الدالة أو الفولدر غلط، أو ناقص `__init__.py` (جدول خطوة 10) |
| مرحلتك `failed` | الكود اتكسر. اقرا الخطأ الكامل في اللوج (شغّل بـ `-v`) |
| `not implemented yet` (exit 3) في `monitor` أو `diff` أو `report` | نفس سبب `skipped`: اسم الملف أو الدالة |
| `MISSING` في `doctor` | الأداة مش متثبتة أو مش في الـ PATH (خطوة 5) |
| `Database schema is vX ...` | ملف `marsadix.db` المحلي قديم. امسحه وشغّل تاني |
| `Activate.ps1` ممنوع (Windows) | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| الألوان في الـ banner مش ظاهرة | ترمنال قديم. استخدم Windows Terminal أو ترمنال VS Code |
| أداة بطيئة أو واقفة | الـ `run_tool` فيها timeout، فمش هتفضل واقفة للأبد. زوّد الـ timeout لو عايز |

> الـ Pull Requests والـ Issues بيوضّحوا مين عمل إيه، وده نفسه المطلوب في العرض النهائي لمبادرة رواد مصر الرقمية (إظهار مسؤولية كل عضو).
