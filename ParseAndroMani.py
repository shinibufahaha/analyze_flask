# -*- coding: utf-8 -*-
import xml.etree.ElementTree as ET
import json
import os
import io
import logging
from javax.xml.transform import TransformerFactory, OutputKeys
from javax.xml.transform.dom import DOMSource
from javax.xml.transform.stream import StreamResult
from java.io import StringWriter
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code import DecompilationOptions, IDecompilerUnit, DecompilationContext
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IDexDecompilerUnit
from com.pnfsoftware.jeb.core.units.code.android import IApkUnit
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.actions import (
    ActionContext,
    ActionOverridesData,
    Actions,
    ActionXrefsData,
)


class ParseAndroMani(IScript):
    def __init__(self):
        self.package_xml_path = "/home/hcsl_xj/project/phenom_packages.xml"
        self.permission_info = self.get_permission_info(self.package_xml_path)
        self.root = None
        self.apk_path = ""
        self.sink_method_sigs = ["Landroid/content/Context;->startActivity(Landroid/content/Intent;)V", "Landroid/content/Context;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V",
                    "Landroid/content/Context;->startActivityAsUser(Landroid/content/Intent;Landroid/os/UserHandle;)V", "Landroid/content/Context;->startActivityAsUser(Landroid/content/Intent;Landroid/os/Bundle;Landroid/os/UserHandle;)V", 
                    "Landroid/app/Activity;->startActivityForResult(Landroid/content/Intent;I)V", "Landroid/app/Activity;->startActivityForResult(Landroid/content/Intent;ILandroid/os/Bundle;)V"]
        self.dfs_depth = 15
        self.debug = True

    def init_log():
        pass

    def debug_print(self, msg):
        if self.debug:
            print(msg)

    # 四大组件对应的入口函数
    ENTRYS = {
        "a": [
            "onNewIntent(Landroid/content/Intent;)V",
            "onActivityResult(IILandroid/content/Intent;)V",
            "onCreate(Landroid/os/Bundle;)V",
            "onStart()V",
            "onResume()V"
        ],
        "p": [
            "insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;", 
            "query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;", 
            "delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I", 
            "update(Landroid/net/Uri;Landroid/content/ContentValues;[Ljava/lang/String;Ljava/lang/String;)I", 
            "call(Ljava/lang/String;[Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;", 
            "openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;", 
            "openAssetFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;", 
            "openFileHelper(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;", 
            "openTypedAssetFile(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/ParcelFileDescriptor;", 
            "applyBatch(Ljava/util/ArrayList;) [Landroid/content/ContentProviderResult;", # 修正：applyBatch参数通常是ArrayList

        ],
        "s": [
            "onStartCommand(Landroid/content/Intent;II)I", 
            "onBind(Landroid/content/Intent;)Landroid/os/IBinder;",
        ],
        "r": [
            "onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
        ],
    }
    
    NS = "{http://schemas.android.com/apk/res/android}"
    

    ATTRS = {
        "NAME": NS + "name",
        "PERMISSION": NS + "permission",
        "EXPORTED": NS + "exported",
        "ENABLED": NS + "enabled",
        "READ_PERMISSION": NS + "readPermission",
        "WRITE_PERMISSION": NS + "writePermission",
        "AUTH": NS + "authorities",
        "SCHEME": NS + "scheme",
        "HOST": NS + "host",
        "PATH": NS + "path",
        "PATH_PREFIX": NS + "pathPrefix",
    }

    def get_permission_info(self, package_xml_path):
        tree = ET.parse(package_xml_path)
        root = tree.getroot()
        permission_info = {}
        permission_info["normal"] = []
        permission_info["dangerous"] = []
        permission_info["signature"] = []
        for item in root.findall(".//permissions/item"):
            name = item.get('name')
            protection = item.get('protection')
            if protection == '0' or protection is None:  # normal 权限的保护级别是 0
                permission_info["normal"].append(name)
            elif protection == '1':
                permission_info["dangerous"].append(name)
            else:
                permission_info["signature"].append(name)
        return permission_info

    def _is_component_accessible(self, element):
        """
        通用组件过滤逻辑：针对新版本应用，必须显式 exported="true"
        且 enabled 不为 "false" (默认为 true)
        """
        exported = element.get(self.ATTRS["EXPORTED"])
        enabled = element.get(self.ATTRS["ENABLED"], "true").lower()
        
        # 过滤权限：如果定义了权限且该权限不是普通权限，则视为不可访问
        permission = element.get(self.ATTRS["PERMISSION"])
        if permission and permission in self.permission_info["signature"]:
            return False
            
        return exported == "true" and enabled != "false"

    def run(self, ctx):
        # ... 获取 apk 和 man 的代码 ...
                # 1. Retrieve input directory from command line arguments
        argv = ctx.getArguments()
        if len(argv) < 1:
            print("ERROR: Please provide the path to the APK folder.")
            print("Usage: jeb_linux.sh --gc --script=jeb_batch_analyze.py -- <apk_dir>")
            return

        input_dir = argv[0]
        if not os.path.isdir(input_dir):
            print("ERROR: Path does not exist or is not a directory: %s" % input_dir)
            return

        # List all APK files
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.endswith(".apk"):
                    apk_path = os.path.join(root, file)
                    apk_name = os.path.basename(apk_path).split(".")[0]
                    androMani_path = os.path.dirname(apk_path) + "/" + apk_name + ".json"
                    if os.path.exists(androMani_path):
                        continue

                    self.analyze_single_apk(ctx, apk_path)

        # self.analyze_single_apk(ctx, "/home/hcsl_xj/project/yoyo.apk")

        print("All tasks completed.")


    def analyze_single_apk(self, ctx, apk_path):
        self.apk_path = apk_path
        print("\n" + "="*60)
        apk_name = os.path.basename(apk_path).split(".")[0]
        output_path = os.path.dirname(apk_path) + "/" + apk_name + "_call_chain.json"
        # 1. 获取 EnginesContext
        eng_ctx = ctx.getEnginesContext()
        prj = None
        prj_key = None

        try:
            unit = ctx.open(apk_path)
            if not unit:
                return
            prj = ctx.getMainProject()
            assert prj, 'Need a project'
            prj_key = prj.getKey()
            
            # get AndroidManifest.xml
            apk = prj.findUnit(IApkUnit)
            assert apk, 'Need an APK unit'

            manifest = apk.getManifest()
            assert manifest, 'Need a manifest'
            xmldoc = manifest.getDocument()

            # 2) 将 Java DOM 转换为标准字符串 (避免美化带来的格式错误)
            sw = StringWriter()
            transformer = TransformerFactory.newInstance().newTransformer()
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no")
            transformer.setOutputProperty(OutputKeys.METHOD, "xml")
            transformer.setOutputProperty(OutputKeys.INDENT, "yes")
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8")
            transformer.transform(DOMSource(xmldoc), StreamResult(sw))

            clean_xml_str = sw.toString()

            
            self.root = ET.fromstring(clean_xml_str.encode('utf-8'))
            package_name = self.root.get('package')

            component_data = self.get_component_data()
            
            self.save_to_json(component_data, os.path.dirname(apk_path) + "/" + apk_name + ".json")

            ## 开始从component_data的暴露组件入口函数开始进行dfs搜索
            for component in component_data:
                if component["type"] == "a":
                    for entry in self.ENTRYS["a"]:
                        entry_sig = "L" + "/".join(component["name"].split(".")) + ";->" + entry
                        print("Searching path for " + entry_sig + " ...")
                        has_pivot = False
                        path = self.find_path_dfs_enhanced(ctx, entry_sig, self.dfs_depth, set(), [entry_sig], has_pivot)

                        if path:
                            print("\n[SUCCESS] Path found for " + entry_sig + " Saving to JSON...")
                            self.save_chain_to_json(ctx, path, output_path)
                elif component["type"] == "p" or component["type"] == "s":
                    
                    class_sig = "L" + "/".join(component["name"].split(".")) + ";"
                    print(class_sig)
                    decompiled_class_code = self.decompile_class(ctx, class_sig)
                    output_file = os.path.dirname(apk_path) + "/" + "decompiled_code_" + component["type"] + ".json"
                  
                    all_results = {}

                    # 2. 检查文件是否存在且不为空
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        try:
                            # 使用 io.open 以支持 utf-8 编码，防止 Python 2 的编码崩溃
                            with io.open(output_file, 'r', encoding='utf-8') as f:
                                all_results = json.load(f)
                        except Exception as e:
                            print("读取 JSON 失败，初始化为空字典: " + str(e))
                            all_results = {}

                    all_results[component["name"]] = decompiled_class_code

                    # 4. 写入文件
                    with io.open(output_file, 'w', encoding='utf-8') as f:
                        # 先将对象转为 unicode 字符串
                        json_str = json.dumps(all_results, ensure_ascii=False, indent=4)
                        # 确保是 unicode 类型再写入 (针对 Python 2)
                        if isinstance(json_str, str) and hasattr(__builtins__, 'unicode'):
                            json_str = json_str.decode('utf-8')
                        f.write(json_str)



        except Exception as e:
            print("An exception occurred: %s" % str(e))
        
        finally:
            if prj_key and eng_ctx:
                print("Attempting to unload project: %s" % prj_key)
                # 使用 IEnginesContext 的 unloadProject 方法
                success = eng_ctx.unloadProject(prj_key)
                
                if success:
                    print("Project %s unloaded from EnginesContext." % prj_key)
                else:
                    # 如果返回 False，可能是 Key 不正确或项目已被卸载
                    print("Unload failed for key: %s" % prj_key)
                
                self.dexUnit = None

    
    def get_activity_data(self):
        if self.root is None: return None
        
        activity_data = []
        for activity in self.root.findall(".//activity"):
            name = activity.get(self.ATTRS["NAME"])
            exported = activity.get(self.ATTRS["EXPORTED"])
            has_intent_filter = len(activity.findall('intent-filter')) > 0
            permission = activity.get(self.ATTRS["PERMISSION"])

            if not name:
                continue
            if activity.get(self.ATTRS["ENABLED"]) == "false":
                continue
            if exported == "false":
                continue
            if exported is None and not has_intent_filter:
                continue
            if permission is not None and permission in self.permission_info["signature"]:
                continue  

            info = {
                "name": activity.get(self.ATTRS["NAME"]),
                "permission": activity.get(self.ATTRS["PERMISSION"]),
                "data": [],
                "isBrowsable": False,
                "exported": "true",
                "type": "a"
            }

            for itf in activity.findall("intent-filter"):
                # 检查 Browsable 状态
                if any("BROWSABLE" in (c.get(self.ATTRS["NAME"]) or "") for c in itf.findall("category")):
                    info["isBrowsable"] = True

                # 提取 Data 信息
                for d in itf.findall("data"):
                    d_info = {k: d.get(self.ATTRS[v]) for k, v in [
                        ("scheme", "SCHEME"), ("host", "HOST"), 
                        ("path", "PATH"), ("pathPrefix", "PATH_PREFIX")
                    ]}
                    # 仅保留非空项并去重
                    if any(d_info.values()) and d_info not in info["data"]:
                        info["data"].append(d_info)
            
            activity_data.append(info)
        return activity_data

    def get_provider_data(self):
        if self.root is None: return None
        
        provider_data = []
        for provider in self.root.findall(".//provider"):
            if provider.get(self.ATTRS["ENABLED"]) == "false":
                continue
            exported = provider.get(self.ATTRS["EXPORTED"])
            if exported is None or exported == "false":
                continue
            name = provider.get(self.ATTRS["NAME"])
            permission = provider.get(self.ATTRS["PERMISSION"])   
            r_perm = provider.get(self.ATTRS["READ_PERMISSION"])
            w_perm = provider.get(self.ATTRS["WRITE_PERMISSION"])
            # TODO,只要有path-permission，就认为存在风险
            has_path_permission = len(provider.findall("path-permission")) > 0
                
            # 过滤危险读写权限

            if permission is None or permission not in self.permission_info["signature"] \
            or r_perm is None or r_perm not in self.permission_info["signature"] \
            or w_perm is None or w_perm not in self.permission_info["signature"] or has_path_permission:

                path_perms = []
                for pp in provider.findall("path-permission"):
                    pp_data = {k: pp.get(self.ATTRS[v]) for k, v in [
                        ("pathPrefix", "PATH_PREFIX"), ("permission", "PERMISSION"),
                        ("readPermission", "READ_PERMISSION"), ("writePermission", "WRITE_PERMISSION")
                    ]}
                    path_perms.append(pp_data)

                provider_data.append({
                    "name": provider.get(self.ATTRS["NAME"]),
                    "authorities": provider.get(self.ATTRS["AUTH"]),
                    "permission": provider.get(self.ATTRS["PERMISSION"]),
                    "readPermission": r_perm,
                    "writePermission": w_perm,
                    "path-permission": path_perms,
                    "type": "p"
                })
        return provider_data

    def get_service_data(self):
        if self.root is None: return None
        return [{
            "name": s.get(self.ATTRS["NAME"]),
            "permission": s.get(self.ATTRS["PERMISSION"]),
            "type": "s"
        } for s in self.root.findall(".//service") if self._is_component_accessible(s)]

    def get_receiver_data(self):
        if self.root is None: return None
        
        receiver_data = []
        for receiver in self.root.findall(".//receiver"):
            if not self._is_component_accessible(receiver):
                continue
                
            actions = []
            for itf in receiver.findall("intent-filter"):
                actions.extend([a.get(self.ATTRS["NAME"]) for a in itf.findall("action")])
            
            receiver_data.append({
                "name": receiver.get(self.ATTRS["NAME"]),
                "permission": receiver.get(self.ATTRS["PERMISSION"]),
                "action": list(set(actions)), # 去重
                "type": "r"
            })
        return receiver_data
    
    def get_component_data(self):
        out_data = []
        activity_data = self.get_activity_data() or []
        provider_data = self.get_provider_data() or []
        service_data = self.get_service_data() or []
        receiver_data = self.get_receiver_data() or []

        out_data.extend(activity_data)
        out_data.extend(provider_data)
        out_data.extend(service_data)
        out_data.extend(receiver_data)
        return out_data
    
        

    def save_to_json(self, data, output_file):
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            print("Data successfully saved to " + output_file)
        except IOError as e:
            print("Error saving to JSON: " + str(e))

    # Intent_direct导致的launchAnywhere漏洞，调用链上存在getParcelable或者getParcelableExtra函数，且返回类型是intent；sink点是startActivity类函数
    def intent_direct(self, ctx):
        """
        LaunchAnywhere 检测入口
        逻辑：查找一条路径，该路径必须先后经过 Intent 转换函数和 Sink 函数
        """
        # 定义特征函数（Source/Intermediate）
        # 只要调用链中包含这些，就认为该路径具有“重定向”特征
        pivot_methods = [
            "getParcelableExtra",
            "getParcelable",
            "getSerializableExtra"
        ]
        
        # 获取所有入口点（如 Activity 的 onCreate, Receiver 的 onReceive 等）
        entry_points = self.get_all_entry_points(ctx)
        all_vulnerabilities = []

        for entry_sig in entry_points:
            # 初始状态 has_pivot 为 False
            paths = self.find_path_dfs_enhanced(
                ctx, entry_sig, depth=10, 
                visited=set(), 
                current_path=[entry_sig], 
                has_pivot=False
            )
            if paths:
                all_vulnerabilities.extend(paths)
                
        return all_vulnerabilities

    def find_path_dfs_enhanced(self, ctx, current_sig, depth, visited, current_path, has_pivot):
        if current_sig.startswith("Ljava/lang") or current_sig.startswith("Ljava/util") or current_sig.startswith("Lcom/networkbench") \
        or current_sig.startswith("Lcom/google/gson") or "androidx" in current_sig:
            return []

        # 3. 命中汇点 (Sink)：如果已触发转换逻辑，则记录路径
        if current_sig in self.sink_method_sigs:
            if has_pivot:
                return [current_path]
            return []

        # 4. 递归终止
        if depth <= 0 or current_sig in visited:
            return []

        # 5. 继续搜索
        visited.add(current_sig)
        results = []
        
        called_methods = self.get_called_methods(ctx, current_sig)       

        for next_sig in called_methods:

            if "getParcelable" in next_sig:
                print("has pivot")
                # 还需判断是否将返回值类型转换成了intent
                has_pivot = True
            # 核心：将 has_pivot 状态向下传递
            sub_paths = self.find_path_dfs_enhanced(
                ctx, next_sig, depth - 1, 
                visited.copy(), 
                current_path + [next_sig], 
                has_pivot
            )
            results.extend(sub_paths)
                    
        return results


    def find_path_dfs(self, ctx, current_sig, depth, visited, current_path):

        if current_sig.startswith("Ljava/lang") or current_sig.startswith("Ljava/util") or current_sig.startswith("Lcom/networkbench") \
        or current_sig.startswith("Lcom/google/gson") or "androidx" in current_sig:
            return []
        
        # 2. 命中汇点 (Sink)，返回包含当前路径的双重列表
        if current_sig in self.sink_method_sigs:
            return [current_path]

        # 3. 递归终止条件
        if depth <= 0 or current_sig in visited:
            return []

        # 4. 递归搜索
        all_paths = []
        # 注意：为了允许不同分支共享节点（但同一路径不重复），通常在递归前后做标记
        visited.add(current_sig)
        
        called_methods = self.get_called_methods(ctx, current_sig)
        for next_sig in called_methods:
            # 递归寻找子路径
            results = self.find_path_dfs(ctx, next_sig, depth - 1, visited.copy(), current_path + [next_sig])
            if results:
                all_paths.extend(results) # 合并所有找到的路径
                
        # 如果需要全局防环而非单路径防环，保留 visited.add；
        # 如果允许不同路径经过同一节点，建议使用 visited.copy() 传递
        return all_paths

    def decompile_class(self, ctx, class_sig):
        prj = ctx.getMainProject()
        dexUnit = prj.findUnit(IDexUnit)
        dexDecompilerUnit = DecompilerHelper.getDecompiler(dexUnit)
        assert isinstance(dexDecompilerUnit,IDexDecompilerUnit)

        result = dexDecompilerUnit.decompileClass(class_sig)
        if result:
            decompiled_class_code = dexDecompilerUnit.getDecompiledClassText(class_sig)
            return decompiled_class_code
        else:
            return ""
        
    def get_method_body(self, ctx, target_method_sign):
        prj = ctx.getMainProject()
        dexUnit = prj.findUnit(IDexUnit)
        
        # 2. 获取反编译器单元 (Decompiler Unit)
        # 参照你图片里的 DecompilerHelper 用法
        dexDecompilerUnit = DecompilerHelper.getDecompiler(dexUnit)
        assert isinstance(dexDecompilerUnit,IDexDecompilerUnit)
        # opt = DecompilationOptions.Builder().newInstance().flags(IDecompilerUnit.FLAG_NO_DEFERRED_DECOMPILATION).build()

        # 4. 核心：直接反编译指定的方法
        # decompileMethod 会返回该方法的 Java 源码文本
        result = dexDecompilerUnit.decompileMethod(target_method_sign)
        method_java_code = ""
        if result:
            method_java_code = dexDecompilerUnit.getDecompiledMethodText(target_method_sign)

        return method_java_code
                

    def save_chain_to_json(self, ctx, path, file_name):
        """将链信息保存为 JSON (双重列表结构)"""
        all_chains = []  # 最终的大列表：[ [path1_nodes], [path2_nodes], ... ]
        decompiled_methods = {} 
        class_name = path[0][0].split(";->")[0]
        for single_path in path:
            current_path_nodes = []  # 每一条路径单独存放节点的列表
            for i, sig in enumerate(single_path):
                # 检查缓存
                if sig not in decompiled_methods:
                    method_body = self.get_method_body(ctx, sig)
                    decompiled_methods[sig] = method_body
                
                # 构建当前步骤的节点
                node = {
                    "step": i + 1,
                    "signature": sig,
                    "code": decompiled_methods[sig]
                }
                current_path_nodes.append(node)
            
            # 将这一条完整的路径链存入总列表
            all_chains.append(current_path_nodes)

        try:
            # 以 r+ 模式打开，如果文件不存在则需要处理异常或先创建
            if not os.path.exists(file_name):
                with open(file_name, 'w') as f: f.write("{}")

            with open(file_name, 'r+') as f:
                # 1. 读取内容
                content = f.read().strip()
                json_data = json.loads(content) if content else {}

                # 2. 更新数据
                json_data[class_name] = all_chains

                # 3. 关键：将指针移回文件开头
                f.seek(0)
                
                # 4. 写入新 JSON
                json_str = json.dumps(json_data, indent=4, ensure_ascii=False)
                f.write(json_str)
                
                # 5. 关键：截断文件
                # 如果新数据比旧数据短，防止末尾留下旧数据的“尾巴”
                f.truncate()

            print("Successfully updated: " + os.path.abspath(file_name))
        except Exception as e:
            print("RW mode failed: " + str(e))

    def get_called_methods(self, ctx, method_sig):
        prj = ctx.getMainProject()
        dexUnit = prj.findUnit(IDexUnit)
        called_sigs = []
        method = dexUnit.getMethod(method_sig)
        if not method: return called_sigs
        data = method.getData()
        if not data or not data.getCodeItem(): return called_sigs
        
        cfg = data.getCodeItem().getControlFlowGraph()
        if not cfg: return called_sigs
        for block in cfg.getBlocks():
            for insn in block.getInstructions():
                mnemonic = insn.getMnemonic()
                if mnemonic and 'invoke' in mnemonic.lower():
                    params = insn.getParameters()
                    if params:
                        try:
                            m_idx = params[0].getValue()
                            called_m = dexUnit.getMethod(m_idx)
                            if called_m:
                                sig = called_m.getSignature()
                                # TODO: 被调用者可能在一个block中被调用多次
                                if sig not in called_sigs:
                                    called_sigs.append(sig)
                        except: continue
        return called_sigs


# def get_method_callers(filepath, method_signature):
#     """
#     Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
#     note filepath needs to be an absolute path
#     """
#     if not filepath or not method_signature:
#         raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

#     apk = getOrLoadApk(filepath)
    
#     ret = []
#     codeUnit = apk.getDex()
#     method = codeUnit.getMethod(method_signature)
#     if method is None:
#         print("Method not found: %s" % method_signature)
#         raise_method_not_found(method_signature)
        
#     actionXrefsData = ActionXrefsData()
#     actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, method.getItemId(), None)
#     if codeUnit.prepareExecution(actionContext,actionXrefsData):
#         for i in range(actionXrefsData.getAddresses().size()):
#             ret.append({
#                 "address": actionXrefsData.getAddresses()[i],
#                 "details": actionXrefsData.getDetails()[i]
#             })
#     return ret
