<script setup>
import { ref, computed, onMounted } from "vue";
import { api, authRoleRef } from "../api.js";
import { useRouter } from "vue-router";

const router = useRouter();

// ── 查询状态 ──
const query = ref("");
const mode = ref("url"); // url=完整URL / host=主机名
const isWeb = ref(3);
const pageSize = ref(20);
const daysBack = ref(7);
const searching = ref(false);
const error = ref("");
const result = ref(null); // { total, rest_quota, items, total_raw, total_unique }
const searchMs = ref(0);

// ── 选择与复制 ──
const checked = ref(new Set());
const copyOk = ref(false);
const selectAll = ref(false);

// ── key 状态 ──
const keyStatus = ref(null); // { keys, key_count, defaults }
const keyPanelOpen = ref(false);

const writable = computed(() => authRoleRef.value === "full");

const SYNTAX_HINTS = [
  { label: "域名后缀", tpl: 'domain.suffix="example.com"' },
  { label: "ICP 备案号", tpl: 'icp.number="京ICP备xxxxxxx号"' },
  { label: "网页标题", tpl: 'web.title="后台管理"' },
  { label: "网页正文", tpl: 'web.body="关键字"' },
  { label: "组件产品", tpl: 'app.product="nginx"' },
  { label: "IP", tpl: 'ip="1.2.3.4"' },
];

async function loadKeyStatus() {
  try { keyStatus.value = await api.hunterStatus(); }
  catch { keyStatus.value = null; }
}
onMounted(loadKeyStatus);

async function doSearch(page = 1) {
  const q = query.value.trim();
  if (!q) { error.value = "请输入查询语法"; return; }
  searching.value = true;
  error.value = "";
  result.value = null;
  checked.value = new Set();
  selectAll.value = false;
  const t0 = performance.now();
  try {
    result.value = await api.hunterSearch({
      query: q, page, page_size: pageSize.value, is_web: isWeb.value,
      mode: mode.value, days_back: daysBack.value,
    });
    searchMs.value = Math.round(performance.now() - t0);
  } catch (e) {
    error.value = String(e.message || e);
  } finally {
    searching.value = false;
  }
}

function toggleCheck(v) {
  const next = new Set(checked.value);
  next.has(v) ? next.delete(v) : next.add(v);
  checked.value = next;
  selectAll.value = result.value && next.size === result.value.items.length;
}
function toggleSelectAll() {
  if (!result.value) return;
  if (selectAll.value) { checked.value = new Set(); selectAll.value = false; }
  else {
    checked.value = new Set(result.value.items.map((it) => it.value));
    selectAll.value = true;
  }
}

// 选中集（无勾选时默认全选当前页）
const effectiveValues = computed(() => {
  if (!result.value) return [];
  const items = result.value.items || [];
  return checked.value.size ? items.filter((it) => checked.value.has(it.value)).map((it) => it.value)
    : items.map((it) => it.value);
});

async function copySelected() {
  const values = effectiveValues.value;
  if (!values.length) { error.value = "没有可复制的资产"; return; }
  try {
    const res = await api.hunterCopyText(values);
    await navigator.clipboard.writeText(res.text);
    copyOk.value = true;
    setTimeout(() => (copyOk.value = false), 1500);
  } catch (e) {
    // 剪贴板权限失败时降级：后端返回的文本放进 textarea 让用户手动复制
    error.value = "剪贴板不可用，请手动复制下方文本框";
    manualText.value = values.join("\n");
  }
}
const manualText = ref("");

// 一键带去建任务：写入 localStorage，CreateView/TaskEditModal 读取后预填手动清单
function sendToCreate() {
  const values = effectiveValues.value;
  if (!values.length) return;
  localStorage.setItem("ah_hunter_targets", values.join("\n"));
  router.push("/create");
}
</script>

<template>
  <section class="view hunter-view">
    <header class="page-head">
      <div>
        <h2>Hunter 资产搜索</h2>
        <p class="page-sub">鹰图测绘查询 → 去重 → 一键复制 URL → 粘贴到任务手动清单</p>
      </div>
      <div class="head-actions">
        <button class="head-action" type="button" @click="keyPanelOpen = !keyPanelOpen">
          Key 状态{{ keyStatus ? `（${keyStatus.key_count} 可用）` : "" }}
        </button>
      </div>
    </header>

    <!-- Key 状态面板 -->
    <div v-if="keyPanelOpen && keyStatus" class="hunter-key-panel">
      <table class="hunter-key-table">
        <thead><tr><th>名称</th><th>状态</th><th>剩余配额</th><th>启用</th></tr></thead>
        <tbody>
          <tr v-for="k in keyStatus.keys" :key="k.name">
            <td>{{ k.name }}</td>
            <td :class="{ ok: k.status === '可用', warn: k.status !== '可用' }">{{ k.status }}</td>
            <td>{{ k.rest_quota }}</td>
            <td>{{ k.enabled ? "是" : "否" }}</td>
          </tr>
        </tbody>
      </table>
      <p class="hint">Key 从 hunter_keys.yaml 读取（多 Key 自动轮换）。文件查找顺序：HUNTER_KEYS_YAML 环境变量 → data/hunter_keys.yaml → 本机 hunter1 目录。</p>
    </div>

    <!-- 查询表单 -->
    <div class="hunter-form">
      <div class="hunter-query-row">
        <input
          v-model="query" class="hunter-query" type="text"
          placeholder='Hunter 查询语法，如 domain.suffix="example.com"'
          @keydown.enter="doSearch(1)" :disabled="searching || !writable && !authRoleRef"
        />
        <button class="primary" type="button" :disabled="searching || !query.trim()" @click="doSearch(1)">
          {{ searching ? "查询中…" : "搜索" }}
        </button>
      </div>
      <div class="hunter-opts">
        <label>资产类型
          <select v-model="isWeb">
            <option :value="3">全部</option>
            <option :value="1">Web 资产</option>
            <option :value="2">非 Web</option>
          </select>
        </label>
        <label>提取模式
          <select v-model="mode">
            <option value="url">完整 URL</option>
            <option value="host">主机名（子域收集）</option>
          </select>
        </label>
        <label>每页
          <select v-model.number="pageSize">
            <option :value="20">20</option>
            <option :value="50">50</option>
            <option :value="100">100</option>
          </select>
        </label>
        <label>时间范围
          <select v-model.number="daysBack">
            <option :value="7">近 7 天</option>
            <option :value="14">近 14 天</option>
            <option :value="30">近 30 天</option>
          </select>
        </label>
        <span v-if="result" class="hunter-meta">
          共 {{ result.total }} 条 · 去重后 {{ result.total_unique }} 条 · {{ searchMs }}ms
          <em v-if="result.rest_quota">（{{ result.rest_quota }}）</em>
        </span>
      </div>
      <div class="hunter-syntax-hints">
        <button v-for="h in SYNTAX_HINTS" :key="h.label" type="button" class="mini-action"
                @click="query = h.tpl" :title="h.tpl">{{ h.label }}</button>
      </div>
    </div>

    <div v-if="error" class="hunter-error">{{ error }}</div>

    <!-- 手动复制降级文本框 -->
    <div v-if="manualText" class="hunter-manual">
      <p class="hint">请手动复制（Ctrl+A → Ctrl+C）：</p>
      <textarea readonly rows="6" @focus="$event.target.select()">{{ manualText }}</textarea>
    </div>

    <!-- 结果列表 -->
    <div v-if="result" class="hunter-results">
      <div class="hunter-toolbar">
        <label class="hunter-select-all">
          <input type="checkbox" :checked="selectAll" @change="toggleSelectAll" />
          全选（{{ result.items.length }}）
        </label>
        <span class="hunter-selected-info">
          已选 {{ checked.size || "0" }} 条<template v-if="!checked.size && result.items.length">（复制时默认全部）</template>
        </span>
        <span class="spacer"></span>
        <button class="mini-action" type="button" :disabled="!result.items.length" @click="copySelected">
          {{ copyOk ? "✓ 已复制" : "一键复制 URL" }}
        </button>
        <button class="mini-action ok" type="button" :disabled="!result.items.length" @click="sendToCreate">
          带去新建任务 →
        </button>
      </div>

      <div class="hunter-list">
        <div v-for="it in result.items" :key="it.value" class="hunter-item">
          <input type="checkbox" :checked="checked.has(it.value)" @change="toggleCheck(it.value)" />
          <a :href="it.value" target="_blank" rel="noopener noreferrer" class="hunter-url" :title="it.value">{{ it.value }}</a>
          <span v-if="it.title" class="hunter-title" :title="it.title">{{ it.title }}</span>
          <span v-if="it.company" class="hunter-company">{{ it.company }}</span>
          <span v-if="it.status_code" class="hunter-code">{{ it.status_code }}</span>
        </div>
        <div v-if="!result.items.length" class="empty">没有查询到资产，换个语法或放宽时间范围试试</div>
      </div>
    </div>

    <div v-else-if="!searching && !error" class="empty hunter-empty">
      输入 Hunter 查询语法开始搜索
      <span class="hint">查询结果去重后可一键复制 URL，直接粘贴到「新建任务」的手动目标清单</span>
    </div>
  </section>
</template>
