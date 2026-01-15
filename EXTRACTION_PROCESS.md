# Extraction Process

This file offers an overview of how GreedyBear extracts and processes T-Pot data. The ExtractionJob shown in the diagram runs every 10 minutes by default.

```mermaid
sequenceDiagram
    participant Job as ExtractionJob
    participant Pipeline as ExtractionPipeline
    participant Elastic as ElasticRepository
    participant Factory as StrategyFactory
    participant Strategy as ExtractionStrategy
    participant Processor as IocProcessor
    participant Repo as IocRepository
    
    Job->>Pipeline: execute()
    Pipeline->>Elastic: search(minutes_back)
    Elastic-->>Pipeline: hits[]
    
    loop Each honeypot
        Pipeline->>Factory: get_strategy(honeypot)
        Factory-->>Pipeline: strategy
        Pipeline->>Strategy: extract_from_hits(hits)
        Strategy->>Strategy: iocs_from_hits(hits)
        
        loop Each IOC
            Strategy->>Processor: add_ioc(ioc)
            Processor->>Repo: get_ioc_by_name(name)
            alt IOC exists
                Processor->>Processor: merge_iocs()
                Processor->>Repo: save(ioc)
            else New IOC
                Processor->>Repo: save(ioc)
            end
        end
    end
    
    Pipeline->>Pipeline: UpdateScores()
```

A single `ExtractionPipeline` instance (now in `greedybear/extraction/extraction_pipeline.py`) orchestrates the extraction of all available honeypots. It uses the `ElasticRepository` to receive a list of all honeypot hits from a certain time window. For each honeypot it gets the corresponding `ExtractionStrategy` (found in `greedybear/extraction/strategies/`), which contains all the extraction logic that is specific for a certain type of honeypot (e.g. Cowrie). The `ExtractionStrategy` uses this logic to create IOC objects and hands them to the `IocProcessor` (located in `greedybear/extraction/ioc_processor.py`), which is responsible for processing them so they can be written to the database via the `IocRepository`.
