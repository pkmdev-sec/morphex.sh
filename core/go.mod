module github.com/morphex/integrations/synapse

go 1.22

require github.com/synapse/engine v0.0.0

require github.com/morphex/api v0.0.0

require github.com/morphex/web v0.0.0

require github.com/yalue/onnxruntime_go v1.13.0 // indirect

replace github.com/synapse/engine => ../engine

replace github.com/morphex/api => ../api

replace github.com/morphex/integrations/synapse => ./

replace github.com/morphex/web => ../web
