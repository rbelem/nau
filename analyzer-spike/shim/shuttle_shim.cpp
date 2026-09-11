// shuttle_shim.cpp — minimal extern "C" bridge over Luau's type analyzer.
//
// Mirrors how CLI/src/Analyze.cpp (luau-analyze) drives the analyzer:
//   FileResolver (sources) + ConfigResolver (mode) -> Frontend ->
//   registerBuiltinGlobals + freeze -> frontend.check(module) -> CheckResult.errors.
//
// Two entry patterns, so the spike can measure both honestly:
//   * shuttle_check_once          — construct a fresh Frontend per check (subprocess model)
//   * shuttle_checker_new/_check  — reuse one Frontend across many checks (worker model)
//
// Positions returned are 1-based lines / 1-based begin columns, end column
// exclusive (same convention luau-analyze prints: `line.col-line.col`).

#include "Luau/BuiltinDefinitions.h"
#include "Luau/Config.h"
#include "Luau/Error.h"
#include "Luau/FileResolver.h"
#include "Luau/Frontend.h"
#include "Luau/TypeArena.h"
#include "Luau/TypeInfer.h"

#include <exception>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{

// Serves all modules from an in-memory table. `require("name")` resolves to a
// module only if that name was seeded (checker or Rust side decides what is
// visible — the production hook point for store-backed resolution).
struct InMemoryResolver final : Luau::FileResolver
{
    std::unordered_map<Luau::ModuleName, std::string> sources;

    std::optional<Luau::SourceCode> readSource(const Luau::ModuleName& name) override
    {
        auto it = sources.find(name);
        if (it == sources.end())
            return std::nullopt;
        // Type must be Module for a module to be requirable ("ModuleScript"
        // semantics); Script is for entry scripts like luau-analyze's stdin.
        return Luau::SourceCode{it->second, Luau::SourceCode::Module};
    }

    std::optional<Luau::ModuleInfo> resolveModule(const Luau::ModuleInfo* context, Luau::AstExpr* node) override
    {
        if (auto* expr = node->as<Luau::AstExprConstantString>())
        {
            Luau::ModuleName name{expr->value.data, expr->value.size};
            if (sources.count(name))
                return Luau::ModuleInfo{name};
        }
        return std::nullopt;
    }
};

// Per-module analysis mode. luau-analyze sets `defaultConfig.mode` from
// `--mode=strict`; there is no Mode field on FrontendOptions in 0.663 — mode
// flows through the ConfigResolver.
struct FixedConfigResolver final : Luau::ConfigResolver
{
    Luau::Config defaultConfig;

    FixedConfigResolver() = default;
    explicit FixedConfigResolver(Luau::Mode mode)
    {
        defaultConfig.mode = mode;
    }

    const Luau::Config& getConfig(const Luau::ModuleName& name) const override
    {
        return defaultConfig;
    }
};

} // namespace

struct ShuttleChecker
{
    InMemoryResolver fileResolver;
    FixedConfigResolver configResolver;
    Luau::Frontend* frontend = nullptr;
};

struct ShuttleCheckResult
{
    std::vector<Luau::TypeError> errors;
    std::vector<std::string> messages; // parallel to `errors`; pointers handed to Rust stay valid until free
    int timeoutHits = 0;
};

extern "C"
{

    // Reusable checker (worker model): builtin globals are registered and
    // frozen once per checker, not once per check.
    ShuttleChecker* shuttle_checker_new(int strict)
    {
        auto* checker = new ShuttleChecker();
        checker->configResolver.defaultConfig.mode = strict ? Luau::Mode::Strict : Luau::Mode::Nonstrict;
        Luau::FrontendOptions options;
        options.retainFullTypeGraphs = false;
        options.runLintChecks = false;
        checker->frontend = new Luau::Frontend(&checker->fileResolver, &checker->configResolver, options);
        Luau::registerBuiltinGlobals(*checker->frontend, checker->frontend->globals);
        Luau::freeze(checker->frontend->globals.globalTypes);
        return checker;
    }

    void shuttle_checker_free(ShuttleChecker* checker)
    {
        if (!checker)
            return;
        delete checker->frontend;
        delete checker;
    }

    // Make an extra module visible to readSource/resolveModule (typed prelude,
    // pkgs/lib templates). Copies the source.
    void shuttle_checker_seed_module(ShuttleChecker* checker, const char* name, const char* source, size_t len)
    {
        checker->fileResolver.sources[Luau::ModuleName(name)] = std::string(source, len);
    }

    // Run --!strict type checking of one in-memory module. Never throws across
    // the boundary; catastrophic failures come back as a single synthetic
    // diagnostic at 1:1.
    ShuttleCheckResult* shuttle_checker_check(ShuttleChecker* checker, const char* name, const char* source, size_t len)
    {
        auto result = std::make_unique<ShuttleCheckResult>();
        try
        {
            Luau::ModuleName moduleName(name);
            checker->fileResolver.sources[moduleName] = std::string(source, len);

            Luau::CheckResult cr = checker->frontend->check(moduleName);
            for (const Luau::TypeError& err : cr.errors)
            {
                result->errors.push_back(err);
                result->messages.push_back(Luau::toString(err));
            }
            result->timeoutHits = static_cast<int>(cr.timeoutHits.size());
        }
        catch (const std::exception& e)
        {
            // InternalCompilerError and friends derive from std::exception;
            // surface as one synthetic 1:1 diagnostic instead of unwinding
            // across the C boundary.
            result->errors.push_back(Luau::TypeError());
            result->messages.push_back(std::string("shuttle-shim: analyzer exception: ") + e.what());
        }
        catch (...)
        {
            result->errors.push_back(Luau::TypeError());
            result->messages.push_back("shuttle-shim: unknown analyzer exception");
        }
        return result.release();
    }

    int shuttle_error_count(ShuttleCheckResult* result)
    {
        return result ? static_cast<int>(result->errors.size()) : 0;
    }

    // 1-based positions (begin col 1-based, end col exclusive), matching
    // luau-analyze's printed format. `message` points into the result handle;
    // valid until shuttle_check_result_free.
    int shuttle_error_at(
        ShuttleCheckResult* result,
        int index,
        unsigned* beginLine,
        unsigned* beginCol,
        unsigned* endLine,
        unsigned* endCol,
        const char** message,
        size_t* messageLen
    )
    {
        if (!result || index < 0 || static_cast<size_t>(index) >= result->errors.size())
            return -1;

        const Luau::Location& loc = result->errors[static_cast<size_t>(index)].location;
        *beginLine = loc.begin.line + 1;
        *beginCol = loc.begin.column + 1;
        *endLine = loc.end.line + 1;
        *endCol = loc.end.column; // exclusive end column (CLI convention)

        const std::string& msg = result->messages[static_cast<size_t>(index)];
        *message = msg.c_str();
        *messageLen = msg.size();
        return 0;
    }

    int shuttle_timeout_hits(ShuttleCheckResult* result)
    {
        return result ? result->timeoutHits : 0;
    }

    void shuttle_check_result_free(ShuttleCheckResult* result)
    {
        delete result;
    }

} // extern "C"
